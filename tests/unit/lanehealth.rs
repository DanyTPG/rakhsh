use super::*;
use std::time::Duration;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn feed(h: &mut LaneHealth, t: &mut Instant, rtt_ms: u64) {
    h.ping_sent(*t);
    *t += ms(rtt_ms);
    h.pong_recv(*t);
}

fn establish(h: &mut LaneHealth, t: &mut Instant, rtt_ms: u64, n: u32) {
    for _ in 0..n {
        feed(h, t, rtt_ms);
        *t += ms(1000);
    }
}

#[test]
fn two_bad_ticks_do_not_degrade() {
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    establish(&mut h, &mut t, 80, 3);
    for _ in 0..2 {
        feed(&mut h, &mut t, 400);
        assert_eq!(h.tick(t), None);
        t += ms(1000);
    }
    feed(&mut h, &mut t, 80);
    t += ms(1000);
    h.tick(t);
    assert_eq!(h.state(), State::Healthy);
}

#[test]
fn three_bad_ticks_degrade_and_ten_good_ticks_recover() {
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    establish(&mut h, &mut t, 80, 3);
    let mut changes = Vec::new();
    for _ in 0..3 {
        feed(&mut h, &mut t, 400);
        if let Some(s) = h.tick(t) {
            changes.push(s);
        }
        t += ms(1000);
    }
    assert_eq!(changes, vec![State::Degraded]);
    assert_eq!(h.state(), State::Degraded);

    for i in 0..10 {
        feed(&mut h, &mut t, 80);
        let change = h.tick(t);
        t += ms(1000);
        if i < 9 {
            assert_eq!(change, None, "recovered too early at good tick {}", i + 1);
            assert_eq!(h.state(), State::Degraded);
        } else {
            assert_eq!(change, Some(State::Healthy));
        }
    }
    assert_eq!(h.state(), State::Healthy);
}

#[test]
fn a_steady_slow_lane_stays_healthy() {
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    for _ in 0..600 {
        feed(&mut h, &mut t, 320);
        assert_eq!(h.tick(t), None);
        t += ms(1000);
        assert_eq!(h.state(), State::Healthy);
    }
    assert!((h.inflation(t) - 1.0).abs() < 1e-9);
}

#[test]
fn a_stalled_ping_degrades_within_three_ticks() {
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    establish(&mut h, &mut t, 80, 3);
    let sent = t;
    h.ping_sent(sent);
    assert_eq!(h.tick(sent + ms(400)), None, "one bad tick");
    assert_eq!(h.state(), State::Healthy);
    assert_eq!(h.tick(sent + ms(1400)), None, "two bad ticks");
    assert_eq!(h.state(), State::Healthy);
    assert_eq!(h.tick(sent + ms(2400)), Some(State::Degraded));
    assert_eq!(h.state(), State::Degraded);
}

#[test]
fn pongs_match_the_oldest_ping_and_pending_is_bounded() {
    let t = Instant::now();
    let mut h = LaneHealth::new(t);
    h.ping_sent(t);
    h.ping_sent(t + ms(100));
    h.pong_recv(t + ms(300));
    assert_eq!(h.srtt_ms(), Some(300.0), "the oldest ping is matched");
    assert_eq!(h.pending_len(), 1, "the second ping is still waiting");
    for i in 0..10 {
        h.ping_sent(t + ms(400 + i));
    }
    assert_eq!(h.pending_len(), MAX_PENDING);
}

#[test]
fn too_few_samples_never_degrades() {
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    h.ping_sent(t);
    h.pong_recv(t + ms(80));
    t += ms(1000);
    h.ping_sent(t);
    h.pong_recv(t + ms(80));
    t += ms(1000);
    h.ping_sent(t);
    for i in 0..10 {
        assert_eq!(h.tick(t + ms(500 + i * 1000)), None);
        assert_eq!(h.state(), State::Healthy);
    }
}

#[test]
fn a_pong_that_beats_its_own_ping_shifts_every_later_match() {
    // The hazard that the heartbeat ordering guards against. If a pong is
    // handled before its ping is recorded, that pong finds an empty queue and
    // is dropped, the ping is recorded afterwards, and from then on every pong
    // matches the previous ping. Each sample then spans a whole probe period,
    // so the lane reads far slower than it is for as long as it lives.
    let mut t = Instant::now();
    let mut h = LaneHealth::new(t);
    establish(&mut h, &mut t, 80, 3);

    let before = h.srtt_ms().unwrap();
    h.pong_recv(t + ms(80));
    assert_eq!(
        h.srtt_ms(),
        Some(before),
        "a pong with no ping in flight is dropped"
    );

    h.ping_sent(t + ms(95));
    let mut now = t + ms(95);
    for _ in 0..30 {
        now += ms(2000);
        h.ping_sent(now);
        h.pong_recv(now + ms(80));
    }
    assert!(
        h.srtt_ms().unwrap() > 1500.0,
        "one desynced ping keeps every later sample a period too long: {:?}",
        h.srtt_ms()
    );
}

#[test]
fn choose_needs_a_lane() {
    assert_eq!(choose(&[], 0, None), None);
    let one = [Cand {
        id: 7,
        healthy: true,
        srtt_ms: Some(40.0),
        streams: 0,
    }];
    assert_eq!(choose(&one, 5, None), Some(0));
    assert_eq!(choose(&one, 5, Some(7)), None);
}

#[test]
fn choose_prefers_the_idle_lane() {
    let c = [
        Cand {
            id: 1,
            healthy: true,
            srtt_ms: Some(80.0),
            streams: 0,
        },
        Cand {
            id: 2,
            healthy: true,
            srtt_ms: Some(80.0),
            streams: 5,
        },
    ];
    for r in 0..20 {
        assert_eq!(choose(&c, r, None), Some(0), "r = {r}");
    }
}

#[test]
fn choose_never_takes_a_degraded_lane_when_a_healthy_one_exists() {
    let c = [
        Cand {
            id: 1,
            healthy: false,
            srtt_ms: Some(10.0),
            streams: 0,
        },
        Cand {
            id: 2,
            healthy: true,
            srtt_ms: Some(400.0),
            streams: 20,
        },
    ];
    for r in 0..20 {
        assert_eq!(choose(&c, r, None), Some(1), "r = {r}");
    }
}

#[test]
fn choose_still_answers_when_every_lane_is_degraded() {
    let c = [
        Cand {
            id: 1,
            healthy: false,
            srtt_ms: Some(10.0),
            streams: 0,
        },
        Cand {
            id: 2,
            healthy: false,
            srtt_ms: Some(400.0),
            streams: 2,
        },
    ];
    for r in 0..20 {
        assert!(choose(&c, r, None).is_some(), "r = {r}");
    }
}

#[test]
fn cost_driven_load_matches_the_weights() {
    let mut c = [
        Cand {
            id: 1,
            healthy: true,
            srtt_ms: Some(83.0),
            streams: 0,
        },
        Cand {
            id: 2,
            healthy: true,
            srtt_ms: Some(87.0),
            streams: 0,
        },
        Cand {
            id: 3,
            healthy: true,
            srtt_ms: Some(320.0),
            streams: 0,
        },
    ];
    let mut hits = [0usize; 3];
    const PICKS: usize = 6000;
    for r in 0..PICKS {
        let i = choose(&c, r, None).expect("a lane");
        hits[i] += 1;
        c[i].streams += 1;
    }
    let want = [0.452, 0.431, 0.117];
    for i in 0..3 {
        let share = hits[i] as f64 / PICKS as f64;
        assert!(
            (share - want[i]).abs() < 0.10,
            "lane {} got {share:.3}, want about {:.3}",
            c[i].id,
            want[i]
        );
    }
    assert!(hits[2] > 0, "the slowest lane must still get some streams");
}

fn lane(id: u64, healthy: bool, streams: u32) -> Cand {
    Cand {
        id,
        healthy,
        srtt_ms: Some(80.0),
        streams,
    }
}

#[test]
fn migrations_move_off_a_degraded_lane() {
    let c = [lane(1, true, 50), lane(2, false, 1), lane(3, true, 0)];
    assert_eq!(migrations(&c, 2), vec![2]);
}

#[test]
fn migrations_leave_a_busy_healthy_lane_alone() {
    let c = [lane(1, true, 50), lane(2, true, 2)];
    assert!(migrations(&c, 2).is_empty());
}

#[test]
fn migrations_do_nothing_when_everything_is_degraded() {
    let c = [lane(1, false, 50), lane(2, false, 2)];
    assert!(migrations(&c, 2).is_empty());
}

#[test]
fn migrations_ignore_a_degraded_lane_with_no_streams() {
    let c = [lane(1, true, 3), lane(2, false, 0)];
    assert!(migrations(&c, 2).is_empty());
}

#[test]
fn migrations_stop_at_the_per_tick_limit() {
    let c = [lane(1, true, 0), lane(2, false, 5)];
    assert_eq!(migrations(&c, 2), vec![2, 2]);
}
