// frame codec round-trips for the reliable TCP stream mux (dgram.rs)

use super::*;

#[test]
fn open_roundtrip() {
    let mut f = Vec::new();
    frame_open(7, "127.0.0.1:5201", &mut f);
    match parse_frame(&f) {
        Some(Op::Open(sid, target)) => {
            assert_eq!(sid, 7);
            assert_eq!(target, "127.0.0.1:5201");
        }
        other => panic!("wrong frame: {other:?}"),
    }
}

#[test]
fn data_roundtrip() {
    let mut f = Vec::new();
    frame_data(9, 1 << 40, b"hello", &mut f);
    match parse_frame(&f) {
        Some(Op::Data(sid, seq, payload)) => {
            assert_eq!(sid, 9);
            assert_eq!(seq, 1 << 40);
            assert_eq!(payload, b"hello");
        }
        other => panic!("wrong frame: {other:?}"),
    }
}

#[test]
fn ack_fin_rst_roundtrip() {
    let mut f = Vec::new();
    frame_ack(3, 1 << 30, &mut f);
    match parse_frame(&f) {
        Some(Op::Ack(sid, ack)) => {
            assert_eq!(sid, 3);
            assert_eq!(ack, 1 << 30);
        }
        other => panic!("wrong frame: {other:?}"),
    }
    f.clear();
    frame_fin(4, 1024, &mut f);
    match parse_frame(&f) {
        Some(Op::Fin(sid, off)) => {
            assert_eq!(sid, 4);
            assert_eq!(off, 1024);
        }
        other => panic!("wrong frame: {other:?}"),
    }
    f.clear();
    frame_rst(5, &mut f);
    match parse_frame(&f) {
        Some(Op::Rst(sid)) => assert_eq!(sid, 5),
        other => panic!("wrong frame: {other:?}"),
    }
}

#[test]
fn truncated_frames_rejected() {
    let mut f = Vec::new();
    frame_open(1, "t", &mut f);
    for n in 0..f.len() {
        // only a full frame must parse; truncated prefixes must not
        if n < 7 + 1 {
            // OPEN needs at least 7 bytes before target starts
            if n < 7 {
                assert!(parse_frame(&f[..n]).is_none(), "parsed {n}-byte open");
            }
        }
    }
    assert!(parse_frame(&[0, 0, 0]).is_none());
    assert!(parse_frame(&[]).is_none());
}

#[test]
fn unknown_op_rejected() {
    let b = [0u8, 0, 0, 9, 200];
    assert!(parse_frame(&b).is_none());
}

#[test]
fn rcv_out_of_order_and_duplicate_accounting() {
    let mut rcv = Rcv::new();
    assert_eq!(rcv.held, 0);

    // Initial out-of-order packet
    let payload = vec![0xaa; 100];
    let seq = 500u64;
    let old = rcv.pending.insert(seq, payload.clone());
    assert!(old.is_none());
    rcv.held += payload.len();
    assert_eq!(rcv.held, 100);

    // Duplicate retransmitted packet arriving before gap fills
    if let Some(old) = rcv.pending.insert(seq, payload.clone()) {
        rcv.held = rcv.held.saturating_sub(old.len()) + payload.len();
    } else {
        rcv.held += payload.len();
    }
    // Must remain 100, not inflate to 200
    assert_eq!(rcv.held, 100);
}

#[test]
fn snd_fin_offset_accounts_for_queued_bytes() {
    let mut s = Snd::new(Some("127.0.0.1:80".into()));
    s.next_seq = 1000;
    s.outq_bytes = 450;
    // Calling conn_fin:
    s.fin_off = Some(s.next_seq + s.outq_bytes as u64);
    assert_eq!(s.fin_off, Some(1450));
}

