use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const BUCKET: Duration = Duration::from_secs(150);
pub const BAD_INFLATION: f64 = 4.0;
pub const BAD_EXTRA_MS: f64 = 150.0;
pub const GOOD_INFLATION: f64 = 2.0;
pub const ENTER_TICKS: u32 = 3;
pub const EXIT_TICKS: u32 = 10;
pub const MIN_SAMPLES: u64 = 3;
pub const WEIGHT_FLOOR: f64 = 0.25;
pub const MAX_PENDING: usize = 8;
pub const MIGRATE_PER_TICK: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Healthy,
    Degraded,
}

/// One lane's latency health, fed only by ping/pong and a once-a-second tick.
///
/// Path loss on a reliable, ordered carrier shows up as delay, not as lost
/// pongs, so the signals here are the smoothed RTT, a rolling baseline and the
/// age of the oldest ping still in flight. Every method takes the clock as an
/// argument so the whole decision can be tested without sleeping.
#[derive(Clone)]
pub struct LaneHealth {
    srtt_ms: Option<f64>,
    last_ms: Option<f64>,
    bucket_start: Instant,
    cur_min: Option<f64>,
    prev_min: Option<f64>,
    pending: VecDeque<Instant>,
    bad_ticks: u32,
    good_ticks: u32,
    samples: u64,
    state: State,
}

impl LaneHealth {
    pub fn new(now: Instant) -> Self {
        LaneHealth {
            srtt_ms: None,
            last_ms: None,
            bucket_start: now,
            cur_min: None,
            prev_min: None,
            pending: VecDeque::new(),
            bad_ticks: 0,
            good_ticks: 0,
            samples: 0,
            state: State::Healthy,
        }
    }

    pub fn ping_sent(&mut self, now: Instant) {
        if self.pending.len() >= MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(now);
    }

    pub fn pong_recv(&mut self, now: Instant) {
        let Some(sent) = self.pending.pop_front() else {
            return;
        };
        self.roll(now);
        let ms = now.duration_since(sent).as_secs_f64() * 1000.0;
        self.last_ms = Some(ms);
        self.cur_min = Some(self.cur_min.map_or(ms, |m| m.min(ms)));
        self.srtt_ms = Some(match self.srtt_ms {
            None => ms,
            Some(prev) => 0.875 * prev + 0.125 * ms,
        });
        self.samples += 1;
    }

    /// Advance the two baseline buckets so the newest 150 s is the current one.
    fn roll(&mut self, now: Instant) {
        while now.duration_since(self.bucket_start) >= BUCKET {
            self.bucket_start += BUCKET;
            self.prev_min = self.cur_min;
            self.cur_min = None;
        }
    }

    /// Lowest RTT seen in the last two buckets, without mutating anything.
    pub fn baseline_ms(&self, now: Instant) -> Option<f64> {
        let age = now.duration_since(self.bucket_start);
        if age < BUCKET {
            return min_opt(self.prev_min, self.cur_min);
        }
        if age < BUCKET * 2 {
            return self.cur_min;
        }
        None
    }

    /// Last sample, or the age of the oldest unanswered ping when that is worse.
    pub fn cur_ms(&self, now: Instant) -> Option<f64> {
        let stalled = self
            .pending
            .front()
            .map(|t| now.duration_since(*t).as_secs_f64() * 1000.0);
        match (self.last_ms, stalled) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn srtt_ms(&self) -> Option<f64> {
        self.srtt_ms
    }

    /// `cur / baseline`, never below 1.0. Used for lane weights and the score.
    pub fn inflation(&self, now: Instant) -> f64 {
        let (Some(cur), Some(base)) = (self.cur_ms(now), self.baseline_ms(now)) else {
            return 1.0;
        };
        if base <= 0.0 {
            return 1.0;
        }
        (cur / base).max(1.0)
    }

    /// Run the once-a-second state machine. Returns the new state on a change.
    pub fn tick(&mut self, now: Instant) -> Option<State> {
        self.roll(now);
        if self.samples < MIN_SAMPLES {
            return None;
        }
        let (Some(cur), Some(base)) = (self.cur_ms(now), self.baseline_ms(now)) else {
            return None;
        };
        if base <= 0.0 {
            return None;
        }
        let bad = cur >= BAD_INFLATION * base && cur - base >= BAD_EXTRA_MS;
        let good = cur < GOOD_INFLATION * base;
        if bad {
            self.good_ticks = 0;
            self.bad_ticks += 1;
            if self.state == State::Healthy && self.bad_ticks >= ENTER_TICKS {
                self.state = State::Degraded;
                self.bad_ticks = 0;
                self.good_ticks = 0;
                return Some(self.state);
            }
        } else if good {
            self.bad_ticks = 0;
            self.good_ticks += 1;
            if self.state == State::Degraded && self.good_ticks >= EXIT_TICKS {
                self.state = State::Healthy;
                self.bad_ticks = 0;
                self.good_ticks = 0;
                return Some(self.state);
            }
        } else {
            self.bad_ticks = 0;
            self.good_ticks = 0;
        }
        None
    }

    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn min_opt(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Cand {
    pub id: u64,
    pub healthy: bool,
    pub srtt_ms: Option<f64>,
    pub streams: u32,
}

/// Index into `c` for a new stream. None when no lane is allowed.
pub fn choose(c: &[Cand], r: usize, avoid: Option<u64>) -> Option<usize> {
    let allowed = |i: usize| avoid != Some(c[i].id);
    let mut pool: Vec<usize> = (0..c.len())
        .filter(|&i| c[i].healthy && allowed(i))
        .collect();
    if pool.is_empty() {
        pool = (0..c.len()).filter(|&i| allowed(i)).collect();
    }
    if pool.is_empty() {
        return None;
    }
    if pool.len() == 1 {
        return Some(pool[0]);
    }
    let best = pool.iter().filter_map(|&i| c[i].srtt_ms).reduce(f64::min);
    let weight = |sample: Option<f64>| match (best, sample) {
        (Some(b), Some(x)) if x > 0.0 => (b / x).clamp(WEIGHT_FLOOR, 1.0),
        _ => 1.0,
    };
    let cost = |i: usize| (c[i].streams as f64 + 1.0) / weight(c[i].srtt_ms);
    let n = pool.len();
    let idx1 = r % n;
    let idx2 = (idx1 + 1 + (r / n) % (n - 1)) % n;
    let (a, b) = (pool[idx1], pool[idx2]);
    Some(if cost(b) < cost(a) { b } else { a })
}

/// Lane ids to move one stream off. At most `per_tick` entries.
pub fn migrations(c: &[Cand], per_tick: usize) -> Vec<u64> {
    if !c.iter().any(|lane| lane.healthy) {
        return Vec::new();
    }
    let mut degraded: Vec<&Cand> = c
        .iter()
        .filter(|lane| !lane.healthy && lane.streams > 0)
        .collect();
    degraded.sort_by(|a, b| b.streams.cmp(&a.streams).then(a.id.cmp(&b.id)));
    let mut out = Vec::new();
    for lane in degraded {
        for _ in 0..lane.streams {
            if out.len() >= per_tick {
                return out;
            }
            out.push(lane.id);
        }
    }
    out
}

#[cfg(test)]
#[path = "../tests/unit/lanehealth.rs"]
mod tests;
