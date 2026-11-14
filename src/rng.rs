/// A random 64-bit value, used for stream ids and heartbeat jitter.
///
/// Falls back to the wall clock only if the system source fails, so a broken
/// entropy source degrades the spread rather than the tunnel.
pub fn random_u64() -> u64 {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 8];
    if SystemRandom::new().fill(&mut b).is_err() {
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
    }
    u64::from_be_bytes(b)
}
