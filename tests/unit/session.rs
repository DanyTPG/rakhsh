use super::*;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn a_probe_is_recorded_before_it_is_sent() {
    // The guard for the ping-before-send order in spawn_heartbeat. A pong that
    // arrives before the ping is recorded finds an empty queue and is dropped,
    // so the match stays one ping behind for the life of the lane. If someone
    // swaps the two effects in probe_round, the send below observes the record
    // is still missing and this fails.
    use std::sync::atomic::{AtomicBool, Ordering};
    let logged = AtomicBool::new(false);
    let seen_at_send = AtomicBool::new(false);
    let sent = probe_round(7, |_id| logged.store(true, Ordering::SeqCst), async {
        seen_at_send.store(logged.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert!(sent.is_ok());
    assert!(
        seen_at_send.load(Ordering::SeqCst),
        "the ping must be recorded before the frame is handed to the lane"
    );
}

#[tokio::test]
async fn vectored_writes_deliver_every_byte_in_order() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let chunks: Vec<Bytes> = (0..600u32)
        .map(|i| {
            Bytes::from(
                (0..16_000u32 + i)
                    .map(|j| (i + j) as u8)
                    .collect::<Vec<u8>>(),
            )
        })
        .collect();
    let want: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let reader = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let (mut got, mut buf) = (Vec::new(), vec![0u8; 8192]);
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    let (_rd, mut wr) = TcpStream::connect(addr).await.unwrap().into_split();
    for batch in chunks.chunks(17) {
        write_all_chunks(&mut wr, batch).await.unwrap();
    }
    wr.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap(), want);
}
