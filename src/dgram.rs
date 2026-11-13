use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use shabdiz::carrier::{esp, gre, l2, tagged};
use shabdiz::carrier::{tcp::Tcp, udp::Udp, Carrier};
use shabdiz::handshake;
use shabdiz::session::{self, Handle, Role};

use crate::config::Config;

const MAX_FLOWS: usize = 4096;

const FLOW_IDLE: Duration = Duration::from_secs(120);

// flow id reserved for the reliable TCP stream mux (see tcpstream below)
const TCPFLOW: u16 = 0xFFF0;

// reliable TCP-over-datagram tuning: cumulative-ack sliding window with RTO
const TCP_WINDOW: usize = 512 * 1024;
const TCP_CHUNK: usize = 1200;
const TCP_MIN_CHUNK: usize = 200;
const TCP_MAX_CONNS: usize = 256;
const TCP_MAX_RETRIES: u8 = 15;
const TCP_MIN_RTO: Duration = Duration::from_millis(200);
const TCP_MAX_RTO: Duration = Duration::from_secs(4);
const TCP_TICK: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Gre,
    Gre6,
    Esp,
    Tagged,
    L2,
    Udp,
    Tcp,
}

struct Tagged {
    proto: libc::c_int,
    name: &'static str,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    context: &'static str,
}

const TAGGED: &[(&str, Tagged)] = &[
    (
        "shabdiz-ipip",
        Tagged {
            proto: 4,
            name: "IPIP",
            context: "shabdiz-ipip-tags-v1",
        },
    ),
    (
        "shabdiz-6to4",
        Tagged {
            proto: 41,
            name: "6to4",
            context: "shabdiz-6to4-tags-v1",
        },
    ),
    (
        "shabdiz-etherip",
        Tagged {
            proto: 97,
            name: "EtherIP",
            context: "shabdiz-etherip-tags-v1",
        },
    ),
    (
        "shabdiz-l2tp",
        Tagged {
            proto: 115,
            name: "L2TPv3",
            context: "shabdiz-l2tp-tags-v1",
        },
    ),
    (
        "shabdiz-mpls",
        Tagged {
            proto: 137,
            name: "MPLS-in-IP",
            context: "shabdiz-mpls-tags-v1",
        },
    ),
];

fn tagged_spec(carrier: &str) -> Option<&'static Tagged> {
    TAGGED.iter().find(|(n, _)| *n == carrier).map(|(_, s)| s)
}

fn kind_of(carrier: &str) -> Option<Kind> {
    match carrier {
        "shabdiz-gre" => Some(Kind::Gre),
        "shabdiz-gre6" => Some(Kind::Gre6),
        "shabdiz-esp" => Some(Kind::Esp),
        "shabdiz-l2" => Some(Kind::L2),
        "shabdiz-udp" => Some(Kind::Udp),
        "shabdiz-tcp" => Some(Kind::Tcp),
        _ if tagged_spec(carrier).is_some() => Some(Kind::Tagged),
        _ => None,
    }
}

pub fn selected(cfg: &Config) -> bool {
    cfg.carrier.as_deref().and_then(kind_of).is_some()
}

pub fn is_datagram(carrier: &str) -> bool {
    kind_of(carrier).is_some()
}

pub async fn open(cfg: &Config, dialer: bool) -> Result<(Arc<Handle>, Arc<dyn Carrier>)> {
    let kind = cfg
        .carrier
        .as_deref()
        .and_then(kind_of)
        .ok_or_else(|| anyhow!("not a shabdiz carrier"))?;
    let carrier = build_carrier(cfg, kind, dialer).await?;
    let (local, peer, psk) = (
        cfg.secret_key()?,
        cfg.peer_key()?,
        crate::noise::derive_psk(&cfg.token),
    );
    let config = session::Config {
        ring: 1024,
        ..session::Config::default()
    };
    let handle = if dialer {
        let (keys, params) =
            handshake::dial(&*carrier, &local, &peer, &psk, Duration::from_secs(3), 10)
                .await
                .context("shabdiz handshake")?;
        info!("shabdiz up: payload mtu {}", params.payload_mtu);
        session::start(carrier.clone(), keys, params, Role::Dialer, config, None)
    } else {
        let a = handshake::accept(&*carrier, &local, &peer, &psk)
            .await
            .context("shabdiz handshake")?;
        info!("shabdiz up: payload mtu {}", a.params.payload_mtu);
        session::start(
            carrier.clone(),
            a.keys,
            a.params,
            Role::Responder,
            config,
            Some(session::Handshake {
                first: a.first,
                reply: a.reply,
            }),
        )
    };
    Ok((Arc::new(handle), carrier))
}

pub fn describe(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let Some(kind) = cfg.carrier.as_deref().and_then(kind_of) else {
        return out;
    };
    let dialer = dials(cfg);
    out.push(
        "shabdiz: the datagram tunnel — rakhsh's reliable session is not used, so a lost packet \
         costs that packet and nothing behind it"
            .to_string(),
    );
    out.push(format!(
        "  carrier {kind:?}, this end {}",
        if dialer {
            "opens the flow"
        } else {
            "waits to be spoken to"
        }
    ));
    if dialer && cfg.role == "entry" {
        out.push(
            "  WARNING: the entry is opening the flow. On a filtered path that measured 29% loss \
             against 0.001% when the exit opened it — set dial = \"exit\"."
                .to_string(),
        );
    }
    if kind == Kind::Gre {
        out.push(
            "  IP protocol 47, as a bridged Ethernet frame. Measured on the Iranian path: \
             213 Mbit/s outbound at 0.29% loss (100 Mbit/s at 0.00%), 100 Mbit/s inbound at \
             1.39% — against 32 Mbit/s at 0.5-8% for shabdiz-l2."
                .to_string(),
        );
    }
    if kind == Kind::Gre6 {
        out.push(
            "  IPv6 next-header 47, the same bridged Ethernet frame as shabdiz-gre. Worth \
             trying where the v4 path drops protocol 47, since filtering is often built for \
             v4 only; it costs 20 bytes more header, so the carried mtu is 20 lower."
                .to_string(),
        );
    }
    if matches!(kind, Kind::Gre | Kind::Gre6) {
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::Esp {
        out.push(
            "  IP protocol 50, shaped as an ESP packet (SPI and sequence number). Measured on \
             the Iranian path: it crossed where protocol 47 was dropped outright, because \
             blocking ESP would break corporate IPsec."
                .to_string(),
        );
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::Tagged {
        let spec = cfg
            .carrier
            .as_deref()
            .and_then(tagged_spec)
            .expect("a tagged kind always has a spec");
        let (proto, name) = (spec.proto, spec.name);
        out.push(format!(
            "  IP protocol {proto}, shaped as {name} but carrying a token-derived tag and \
             sequence number instead of an inner packet. The tag never begins with 4 or 6, so \
             nothing downstream reads the payload as an IP header — the shape that was measured \
             to be dropped on protocol 47."
        ));
        out.push(
            "  UNMEASURED at volume on the Iranian path: a three-packet probe crossed, but that \
             is exactly the trap sustained UDP fell into. Measure with `rakhsh doctor` before \
             relying on it."
                .to_string(),
        );
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::L2 {
        let (a, b) = shabdiz_ports(&cfg.token);
        out.push(format!(
            "  crafted-TCP ports: the dialling end sends {a} -> {b} (derived from the token; both \
             ends compute the same pair, and it is what to filter a capture on)"
        ));
        out.push(
            "  needs root (CAP_NET_RAW), and drops the kernel's resets for its own port".into(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: no peer_ip and no tunnel_connect — nothing to craft frames to".into(),
            );
        }
    }
    match one_udp_forward(cfg) {
        Ok((l, t)) => out.push(format!("  carries udp {l} -> {t}")),
        Err(e) => out.push(format!("  ERROR: {e}")),
    }
    if let Ok(tf) = tcp_forwards(cfg) {
        for (l, t) in &tf {
            out.push(format!("  carries tcp (reliable stream mux) {l} -> {t}"));
        }
    }
    let ign = ignored(cfg);
    if !ign.is_empty() {
        out.push(format!(
            "  WARNING: a datagram carrier replaces the lane and stream machinery, so these are \
             not read here: {}",
            ign.join(", ")
        ));
    }
    out
}

pub fn ignored(cfg: &Config) -> Vec<&'static str> {
    let mut v = Vec::new();
    if cfg.lanes.is_some() {
        v.push("lanes");
    }
    if cfg.resume {
        v.push("resume");
    }
    if !cfg.link.is_empty() {
        v.push("[[link]]");
    }
    if !cfg.backup_connect.is_empty() {
        v.push("backup_connect");
    }
    if !cfg.peers.is_empty() {
        v.push("[[peer]]");
    }
    if !cfg.inbound.is_empty() {
        v.push("[[inbound]]");
    }
    if cfg.dns.is_some() {
        v.push("[dns]");
    }
    if cfg.max_connections.is_some() {
        v.push("max_connections");
    }
    if cfg.mss_clamp.is_some() {
        v.push("mss_clamp");
    }
    if cfg.encryption.is_some() {
        v.push("encryption (shabdiz always encrypts)");
    }
    if cfg.l3_addr.is_some() {
        v.push("l3_addr");
    }
    let l = &cfg.limits;
    if l.limit.is_some()
        || l.limit_up.is_some()
        || l.limit_down.is_some()
        || l.limit_per_stream.is_some()
        || l.quota.is_some()
    {
        v.push("the limit and quota keys");
    }
    if cfg.forward.iter().filter(|f| !f.udp).count() > TCP_MAX_CONNS {
        v.push("more tcp [[forward]] blocks than the stream mux allows");
    }
    v
}

pub fn validate(cfg: &Config) -> Result<()> {
    let Some(kind) = cfg.carrier.as_deref().and_then(kind_of) else {
        return Ok(());
    };
    one_udp_forward(cfg)?;
    tcp_forwards(cfg)?;
    if matches!(kind, Kind::Gre | Kind::Esp | Kind::Tagged | Kind::L2) {
        peer_host(cfg, cfg.carrier.as_deref().unwrap_or("shabdiz"))?;
    }
    if kind == Kind::Gre6 {
        peer_host6(cfg, "shabdiz-gre6")?;
    }
    Ok(())
}

pub async fn run(cfg: Config) -> Result<()> {
    let kind = cfg
        .carrier
        .as_deref()
        .and_then(kind_of)
        .ok_or_else(|| anyhow!("not a shabdiz carrier"))?;
    let fwd = one_udp_forward(&cfg)?;
    let tfwds = tcp_forwards(&cfg)?;
    let dialer = dials(&cfg);
    if dialer && cfg.role == "entry" {
        warn!(
            "dial = \"entry\" with shabdiz: on a filtered path the side that opens the flow loses \
             far more — measured 29% against 0.001% — so the exit should dial"
        );
    }
    info!(
        "shabdiz {}: carrier {:?}, {} udp {} -> {}, {} tcp forward(s)",
        cfg.role,
        kind,
        if dialer { "dialling," } else { "listening," },
        fwd.0,
        fwd.1,
        tfwds.len()
    );
    let ign = ignored(&cfg);
    if !ign.is_empty() {
        warn!(
            "a datagram carrier does not read these, so they have no effect: {}",
            ign.join(", ")
        );
    }
    let metrics = crate::status::init(&cfg, &cfg.role);
    tokio::spawn(crate::status::serve(crate::status::socket_path(&cfg)));

    let mut backoff = Duration::from_millis(500);
    loop {
        match serve_once(&cfg, dialer, fwd, tfwds.clone(), &metrics).await {
            Ok(()) => backoff = Duration::from_millis(500),
            Err(e) => {
                warn!("shabdiz session ended: {e:#}");
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

fn dials(cfg: &Config) -> bool {
    match cfg.dial.as_deref().unwrap_or("exit") {
        "entry" => cfg.role == "entry",
        _ => cfg.role == "exit",
    }
}

fn one_udp_forward(cfg: &Config) -> Result<(SocketAddr, SocketAddr)> {
    let udp: Vec<_> = cfg.forward.iter().filter(|f| f.udp).collect();
    match udp.len() {
        0 => bail!("a shabdiz carrier needs one `[[forward]]` with `udp = true`"),
        1 => {}
        n => bail!("{n} udp forwards: shabdiz carries one per tunnel, so give each its own config"),
    }
    let f = udp[0];
    Ok((
        f.listen
            .parse()
            .with_context(|| format!("forward listen {}", f.listen))?,
        f.target
            .parse()
            .with_context(|| format!("forward target {}", f.target))?,
    ))
}

// TCP [[forward]] blocks ride the reliable stream mux (tcpstream above); the
// exit learns each target from the OPEN frame, so only the entry needs them.
fn tcp_forwards(cfg: &Config) -> Result<Vec<(SocketAddr, SocketAddr)>> {
    cfg.forward
        .iter()
        .filter(|f| !f.udp)
        .map(|f| {
            Ok((
                f.listen
                    .parse()
                    .with_context(|| format!("forward listen {}", f.listen))?,
                f.target
                    .parse()
                    .with_context(|| format!("forward target {}", f.target))?,
            ))
        })
        .collect()
}

async fn serve_once(
    cfg: &Config,
    dialer: bool,
    fwd: (SocketAddr, SocketAddr),
    tfwds: Vec<(SocketAddr, SocketAddr)>,
    metrics: &crate::status::Metrics,
) -> Result<()> {
    let (handle, carrier) = open(cfg, dialer).await?;
    let label = if dialer { "dialer" } else { "responder" };
    metrics.lane_up(0, cfg.carrier.as_deref().unwrap_or_default());
    let meter = tokio::spawn(meter(handle.clone()));
    let probe = {
        let handle = handle.clone();
        let openvpn = cfg.openvpn.clone();
        tokio::spawn(async move { announce_path_mtu(handle, openvpn).await })
    };
    let report = {
        let handle = handle.clone();
        let carrier = carrier.clone();
        tokio::spawn(async move { report(handle, carrier).await })
    };
    let res = match cfg.role {
        "entry" => entry_bridge(handle.clone(), fwd.0, tfwds).await,
        _ => exit_bridge(handle.clone(), fwd.1).await,
    };
    report.abort();
    probe.abort();
    meter.abort();
    metrics.lane_down(0);
    info!("shabdiz {label} session closed: {:?}", handle.snapshot());
    res
}

async fn announce_path_mtu(handle: Arc<Handle>, openvpn: Option<crate::openvpn::OpenVpn>) {
    let settled = handle.mtu_settled().await;
    let assumed = handle.mtu().assumed();
    if settled >= assumed {
        info!("shabdiz: the path carries the full {assumed}-byte payload (probed)");
        return;
    }
    warn!(
        "shabdiz: the path carries {settled} bytes, not the {assumed} this carrier assumes \
         (probed) — large datagrams would have been lost"
    );
    if let Some(ov) = openvpn {
        let was = assumed.saturating_sub(ov.overhead_bytes());
        let now = settled.saturating_sub(ov.overhead_bytes());
        warn!(
            "openvpn: set tun-mtu {now} on both ends, not the {was} derived from the assumed \
             path, and mssfix {now} mtu with it"
        );
    }
}

fn apply_pacing(cfg: &Config, c: &Arc<dyn Carrier>) {
    let Some(p) = c.pacer() else { return };
    if c.kernel_paced() {
        info!(
            "shabdiz pacing: the kernel holds each packet to its own departure time; this needs \
             the fq qdisc to take effect (`rakhsh optimize` sets it as the default), and without \
             it the gaps are shaped in user space as before"
        );
    } else {
        info!("shabdiz pacing: gaps are shaped in user space");
    }
    if cfg.pace_auto.unwrap_or(false) {
        p.enable_auto_rate();
        info!("shabdiz pacing: adapting the rate from the loss the far end reports");
        return;
    }
    if cfg.pace_burst.is_none() && cfg.pace_gap_us.is_none() && cfg.pace_pps.is_none() {
        info!("shabdiz pacing: shaping bursts only; set pace_pps for a measured rate limit");
        return;
    }
    p.set_manual();
    if let Some(b) = cfg.pace_burst {
        p.set_burst(b);
    }
    if let Some(g) = cfg.pace_gap_us {
        p.set_gap(Duration::from_micros(g));
    }
    if let Some(r) = cfg.pace_pps {
        p.set_rate_pps(r);
    }
    info!(
        "shabdiz pacing (fixed): {} datagram(s) per write, {} us between groups, {} datagrams/s",
        p.burst(),
        cfg.pace_gap_us.unwrap_or(0),
        p.rate_pps()
    );
}

async fn build_carrier(cfg: &Config, kind: Kind, dialer: bool) -> Result<Arc<dyn Carrier>> {
    let c = build_carrier_inner(cfg, kind, dialer).await?;
    apply_pacing(cfg, &c);
    Ok(c)
}

async fn build_carrier_inner(cfg: &Config, kind: Kind, dialer: bool) -> Result<Arc<dyn Carrier>> {
    match kind {
        Kind::Udp => {
            if dialer {
                let peer: SocketAddr = cfg
                    .tunnel_connect
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-udp needs tunnel_connect on the dialling end"))?
                    .parse()
                    .context("tunnel_connect")?;
                let local = shabdiz::carrier::udp::wildcard_for(peer);
                Ok(Arc::new(
                    Udp::connect(local, peer)
                        .await
                        .context("binding the udp carrier")?,
                ))
            } else {
                let local: SocketAddr = cfg
                    .tunnel_listen
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-udp needs tunnel_listen on the listening end"))?
                    .parse()
                    .context("tunnel_listen")?;
                Ok(Arc::new(
                    Udp::bind(local).await.context("binding the udp carrier")?,
                ))
            }
        }
        Kind::Tcp => {
            if dialer {
                let peer: SocketAddr = cfg
                    .tunnel_connect
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-tcp needs tunnel_connect on the dialling end"))?
                    .parse()
                    .context("tunnel_connect")?;
                Ok(Arc::new(
                    Tcp::connect(peer)
                        .await
                        .context("dialling the tcp carrier")?,
                ))
            } else {
                let local: SocketAddr = cfg
                    .tunnel_listen
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-tcp needs tunnel_listen on the listening end"))?
                    .parse()
                    .context("tunnel_listen")?;
                let l = tokio::net::TcpListener::bind(local)
                    .await
                    .context("tcp carrier listen")?;
                Ok(Arc::new(
                    Tcp::accept(&l).await.context("accepting the tcp carrier")?,
                ))
            }
        }
        #[cfg(target_os = "linux")]
        Kind::Gre => {
            let peer_ip = peer_addr(cfg, "shabdiz-gre").await?;
            let (entry_mac, exit_mac) = gre::macs(cfg.token.as_bytes());
            let (local, peer) = if cfg.role == "entry" {
                (entry_mac, exit_mac)
            } else {
                (exit_mac, entry_mac)
            };
            let mtu = gre::path_mtu(1500);
            info!(
                "shabdiz-gre: {peer_ip} on IP protocol 47, mtu {mtu}, up to {} datagrams per syscall",
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                gre::open(peer_ip, local, peer, mtu)
                    .context("opening the GRE carrier (needs root)")?,
            ))
        }
        #[cfg(target_os = "linux")]
        Kind::Gre6 => {
            let peer_ip = peer_addr6(cfg, "shabdiz-gre6").await?;
            let (entry_mac, exit_mac) = gre::macs(cfg.token.as_bytes());
            let (local, peer) = if cfg.role == "entry" {
                (entry_mac, exit_mac)
            } else {
                (exit_mac, entry_mac)
            };
            let mtu = gre::path_mtu6(1500);
            info!(
                "shabdiz-gre6: [{peer_ip}] on IPv6 next-header 47, mtu {mtu}, up to {} datagrams per syscall",
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(gre::open6(peer_ip, local, peer, mtu).context(
                "opening the GRE-over-IPv6 carrier (needs root)",
            )?))
        }
        #[cfg(target_os = "linux")]
        Kind::Esp => {
            let peer_ip = peer_addr(cfg, "shabdiz-esp").await?;
            let (entry_spi, exit_spi) = esp::spis(cfg.token.as_bytes());
            let (local, peer) = if cfg.role == "entry" {
                (entry_spi, exit_spi)
            } else {
                (exit_spi, entry_spi)
            };
            let mtu = esp::path_mtu(1500);
            info!(
                "shabdiz-esp: {peer_ip} on IP protocol 50, spi {local:#010x} <- {peer:#010x}, \
                 mtu {mtu}, up to {} datagrams per syscall",
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                esp::open(peer_ip, local, peer, mtu)
                    .context("opening the ESP carrier (needs root)")?,
            ))
        }
        #[cfg(target_os = "linux")]
        Kind::Tagged => {
            let which = cfg.carrier.as_deref().unwrap_or("shabdiz-ipip");
            let spec = tagged_spec(which).expect("a tagged kind always has a spec");
            let peer_ip = peer_addr(cfg, which).await?;
            let (entry_tag, exit_tag) = tagged::tags(cfg.token.as_bytes(), spec.context);
            let (local, peer) = if cfg.role == "entry" {
                (entry_tag, exit_tag)
            } else {
                (exit_tag, entry_tag)
            };
            let mtu = tagged::path_mtu(1500);
            info!(
                "{which}: {peer_ip} on IP protocol {} ({}), tag {local:#010x} <- {peer:#010x}, \
                 mtu {mtu}, up to {} datagrams per syscall",
                spec.proto,
                spec.name,
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                tagged::open(spec.proto, spec.name, peer_ip, local, peer, mtu)
                    .with_context(|| format!("opening the {which} carrier (needs root)"))?,
            ))
        }
        #[cfg(target_os = "linux")]
        Kind::L2 => {
            let peer_ip = peer_addr(cfg, "shabdiz-l2").await?;
            let (a, b) = shabdiz_ports(&cfg.token);
            let (sport, dport) = if dialer { (a, b) } else { (b, a) };
            let link = l2::discover(peer_ip).context("discovering the interface for shabdiz-l2")?;
            info!(
                "shabdiz-l2: if#{} mtu {}, crafting {sport} -> {dport}, offload available",
                link.ifindex, link.mtu
            );
            Ok(Arc::new(
                l2::L2::open(link, peer_ip, sport, dport, l2::Options::default())
                    .context("opening the layer-2 carrier (needs root)")?,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        Kind::Gre | Kind::Gre6 | Kind::Esp | Kind::Tagged | Kind::L2 => anyhow::bail!(
            "this shabdiz raw carrier needs Linux raw sockets; use shabdiz-udp, shabdiz-tcp, \
             or a stream carrier (quic, wss, tls) on this platform"
        ),
    }
}

pub(crate) fn peer_host<'a>(cfg: &'a Config, what: &str) -> Result<&'a str> {
    let host = match (&cfg.peer_ip, &cfg.tunnel_connect) {
        (Some(h), _) => h.trim(),
        (None, Some(c)) => c.rsplit_once(':').map(|(h, _)| h).unwrap_or(c).trim(),
        (None, None) => bail!("{what} needs peer_ip (or tunnel_connect) to reach the far end"),
    };
    if host.is_empty() {
        bail!("{what}: peer_ip is empty");
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        bail!("{what}: {host} is IPv6; this carrier rides on IPv4");
    }
    Ok(host)
}

#[cfg(target_os = "linux")]
async fn peer_addr(cfg: &Config, what: &str) -> Result<Ipv4Addr> {
    match (&cfg.peer_ip, &cfg.tunnel_connect) {
        (Some(h), _) => peer_ipv4(h, "peer_ip").await,
        (None, Some(c)) => {
            let host = c.rsplit_once(':').map(|(h, _)| h).unwrap_or(c);
            peer_ipv4(host, "tunnel_connect").await
        }
        (None, None) => bail!("{what} needs peer_ip (or tunnel_connect) to reach the far end"),
    }
}

fn shabdiz_ports(token: &str) -> (u16, u16) {
    let k = blake3::derive_key("shabdiz-v1 l2 ports", token.as_bytes());
    let a = 20000 + (u16::from_be_bytes([k[0], k[1]]) % 20000);
    let mut b = 20000 + (u16::from_be_bytes([k[2], k[3]]) % 20000);
    if b == a {
        b = a.wrapping_add(1);
    }
    (a, b)
}

struct Flows {
    by_addr: HashMap<SocketAddr, (u16, Instant)>,
    by_id: HashMap<u16, SocketAddr>,
    next: u16,
}

impl Flows {
    fn new() -> Flows {
        Flows {
            by_addr: HashMap::new(),
            by_id: HashMap::new(),
            next: 1,
        }
    }

    fn id_for(&mut self, addr: SocketAddr) -> u16 {
        let now = Instant::now();
        if let Some((id, seen)) = self.by_addr.get_mut(&addr) {
            *seen = now;
            return *id;
        }
        self.expire(now);
        if self.by_addr.len() >= MAX_FLOWS {
            if let Some((&oldest, _)) = self.by_addr.iter().min_by_key(|(_, (_, seen))| *seen) {
                if let Some((id, _)) = self.by_addr.remove(&oldest) {
                    self.by_id.remove(&id);
                }
            }
        }
        // skip the flow reserved for the TCP stream mux
        while self.next == TCPFLOW {
            self.next = self.next.checked_add(1).unwrap_or(1).max(1);
        }
        self.next = self.next.checked_add(1).unwrap_or(1).max(1);
        let id = self.next;
        self.by_addr.insert(addr, (id, now));
        self.by_id.insert(id, addr);
        id
    }

    fn addr_for(&self, id: u16) -> Option<SocketAddr> {
        self.by_id.get(&id).copied()
    }

    fn expire(&mut self, now: Instant) {
        let gone: Vec<SocketAddr> = self
            .by_addr
            .iter()
            .filter(|(_, (_, seen))| now.duration_since(*seen) > FLOW_IDLE)
            .map(|(a, _)| *a)
            .collect();
        for a in gone {
            if let Some((id, _)) = self.by_addr.remove(&a) {
                self.by_id.remove(&id);
            }
        }
    }
}

async fn entry_bridge(
    h: Arc<Handle>,
    udp_listen: SocketAddr,
    tcp_fwds: Vec<(SocketAddr, SocketAddr)>,
) -> Result<()> {
    let mux = Arc::new(TcpMux::new(h.clone()));
    tokio::spawn(mux.clone().drive());

    // tcp [[forward]] listeners: each accepted conn is one mux sid
    let mut tcp_tasks = Vec::new();
    for (listen, target) in tcp_fwds {
        let l = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind tcp forward {listen}"))?;
        info!("shabdiz entry: forwarding tcp {listen} -> {target} over the tunnel");
        let mux = mux.clone();
        let target = target.to_string();
        tcp_tasks.push(tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = l.accept().await else { break };
                if mux.snd.lock().expect("snd").len() >= TCP_MAX_CONNS {
                    continue;
                }
                let sid = mux
                    .next_sid
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                {
                    let mut out = Vec::with_capacity(target.len() + 7);
                    frame_open(sid, &target, &mut out);
                    mux.h.send(TCPFLOW, &out);
                }
                mux.bridge_conn(sid, conn, target.clone()).await;
            }
        }));
    }

    // udp [[forward]] listener: datagram flows, unchanged
    let sock = Arc::new(
        UdpSocket::bind(udp_listen)
            .await
            .with_context(|| format!("bind {udp_listen}"))?,
    );
    let flows = Arc::new(Mutex::new(Flows::new()));
    info!("shabdiz entry: forwarding udp {udp_listen} over the tunnel");

    let up = {
        let (sock, flows, h) = (sock.clone(), flows.clone(), h.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let flow = flows.lock().expect("flow table").id_for(from);
                h.send(flow, &buf[..n]);
            }
        })
    };

    let mut got = Vec::with_capacity(64);
    let mut last: Option<(u16, SocketAddr)> = None;
    loop {
        if h.recv_batch(&mut got, 64).await == 0 {
            break;
        }
        for (flow, payload) in got.drain(..) {
            if flow == TCPFLOW {
                mux.on_frame(&payload);
                continue;
            }
            let to = match last {
                Some((f, a)) if f == flow => Some(a),
                _ => {
                    let a = flows.lock().expect("flow table").addr_for(flow);
                    if let Some(a) = a {
                        last = Some((flow, a));
                    }
                    a
                }
            };
            if let Some(to) = to {
                let _ = sock.send_to(&payload, to).await;
            }
        }
    }
    up.abort();
    for t in tcp_tasks {
        t.abort();
    }
    bail!("the session ended")
}

async fn exit_bridge(h: Arc<Handle>, target: SocketAddr) -> Result<()> {
    let mux = Arc::new(TcpMux::new(h.clone()));
    tokio::spawn(mux.clone().drive());
    let socks: Arc<Mutex<HashMap<u16, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    info!("shabdiz exit: delivering to udp {target}");

    let mut got = Vec::with_capacity(64);
    loop {
        if h.recv_batch(&mut got, 64).await == 0 {
            break;
        }
        for (flow, payload) in got.drain(..) {
            if flow == TCPFLOW {
                mux.on_frame(&payload);
                continue;
            }
            let known = socks.lock().expect("flow sockets").get(&flow).cloned();
            let sock = match known {
                Some(s) => s,
                None => {
                    let local = shabdiz::carrier::udp::wildcard_for(target);
                    let Ok(s) = UdpSocket::bind(local).await else {
                        continue;
                    };
                    if s.connect(target).await.is_err() {
                        continue;
                    }
                    let s = Arc::new(s);
                    let mut map = socks.lock().expect("flow sockets");
                    if map.len() >= MAX_FLOWS {
                        continue;
                    }
                    match map.entry(flow) {
                        std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(s.clone());
                            drop(map);
                            let (h, socks, s2) = (h.clone(), socks.clone(), s.clone());
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65535];
                                loop {
                                    match s2.recv(&mut buf).await {
                                        Ok(n) if n > 0 => h.send(flow, &buf[..n]),
                                        Ok(_) => {}
                                        Err(_) => break,
                                    }
                                    if h.is_closed() {
                                        break;
                                    }
                                }
                                socks.lock().expect("flow sockets").remove(&flow);
                            });
                            s
                        }
                    }
                }
            };
            let _ = sock.send(&payload).await;
        }
    }
    bail!("the session ended")
}

async fn meter(h: Arc<Handle>) {
    let (mut tx, mut rx) = (0u64, 0u64);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let s = h.snapshot();
        crate::stats::add_tx(s.tx_bytes.saturating_sub(tx) as usize);
        crate::stats::add_rx(s.rx_bytes.saturating_sub(rx) as usize);
        (tx, rx) = (s.tx_bytes, s.rx_bytes);
    }
}

async fn report(h: Arc<Handle>, carrier: Arc<dyn Carrier>) {
    let mut last = (0u64, 0u64);
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let s = h.snapshot();
        if (s.tx_datagrams, s.rx_datagrams) == last {
            continue;
        }
        last = (s.tx_datagrams, s.rx_datagrams);
        info!(
            "shabdiz: tx {} / {:.1} MiB ({} err, {} dropped), rx {} / {:.1} MiB ({} dropped) | \
             loss in {:.2}% out {:.2}% | rtt {} jitter {:.1} ms | {} rejected{}",
            s.tx_datagrams,
            s.tx_bytes as f64 / 1_048_576.0,
            s.tx_errors,
            s.tx_dropped,
            s.rx_datagrams,
            s.rx_bytes as f64 / 1_048_576.0,
            s.rx_dropped,
            s.loss_ratio() * 100.0,
            s.peer_loss_ratio() * 100.0,
            if s.rtt_us == 0 {
                "— (the dialling end measures it)".to_string()
            } else {
                format!("{:.1} ms", s.rtt_us as f64 / 1000.0)
            },
            s.jitter_us as f64 / 1000.0,
            s.rejected,
            match carrier.pacer() {
                Some(p) => format!(
                    " | pacing {} per write, {}",
                    p.burst(),
                    match p.rate_pps() {
                        0 => "no rate limit".to_string(),
                        r => format!("{r} datagrams/s"),
                    }
                ),
                None => String::new(),
            },
        );
    }
}

pub(crate) fn peer_host6<'a>(cfg: &'a Config, what: &str) -> Result<&'a str> {
    let host = match (&cfg.peer_ip, &cfg.tunnel_connect) {
        (Some(h), _) => h.trim(),
        (None, Some(c)) => strip_port6(c.trim()),
        (None, None) => bail!("{what} needs peer_ip (or tunnel_connect) to reach the far end"),
    };
    if host.is_empty() {
        bail!("{what}: peer_ip is empty");
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        bail!("{what}: {host} is IPv4; use shabdiz-gre for that, this one rides on IPv6");
    }
    Ok(host)
}

fn strip_port6(addr: &str) -> &str {
    if let Some(end) = addr.strip_prefix('[').and_then(|r| r.find(']')) {
        return &addr[1..=end];
    }
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        return addr;
    }
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
}

#[cfg(target_os = "linux")]
async fn peer_addr6(cfg: &Config, what: &str) -> Result<std::net::Ipv6Addr> {
    let host = peer_host6(cfg, what)?;
    peer_ipv6(host, what).await
}

#[cfg(target_os = "linux")]
pub(crate) async fn peer_ipv6(host: &str, what: &str) -> anyhow::Result<std::net::Ipv6Addr> {
    use anyhow::{bail, Context};
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        bail!("{what} is empty");
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(ip);
    }
    let found = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("resolving {what} {host}"))?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V6(v6) => Some(v6),
            std::net::IpAddr::V4(_) => None,
        });
    match found {
        Some(ip) => {
            tracing::info!("{what} {host} resolved to {ip}");
            Ok(ip)
        }
        None => bail!("{what} {host} has no AAAA record; this carrier rides on IPv6"),
    }
}

pub(crate) async fn peer_ipv4(host: &str, what: &str) -> anyhow::Result<std::net::Ipv4Addr> {
    use anyhow::{bail, Context};
    let host = host.trim();
    if host.is_empty() {
        bail!("{what} is empty");
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(ip);
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        bail!("{what} {host} is IPv6; this carrier rides on IPv4");
    }
    let found = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("resolving {what} {host}"))?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        });
    match found {
        Some(ip) => {
            tracing::info!("{what} {host} resolved to {ip}");
            Ok(ip)
        }
        None => bail!("{what} {host} has no A record; this carrier rides on IPv4"),
    }
}

#[cfg(test)]
#[path = "../tests/unit/dgram_peer.rs"]
mod peer_tests;

#[cfg(test)]
#[path = "../tests/unit/dgram_tcp.rs"]
mod tcp_tests;

// ---------------------------------------------------------------------------
// reliable TCP stream mux over the datagram session
//
// The shabdiz session Handle is a lossy per-flow datagram channel. Raw
// datagram carriers (shabdiz-gre/esp/...) expose only that channel, so a TCP
// forward needs its own reliability layer on top: per-sid sliding window with
// RTO retransmit and cumulative ack, carried on one reserved flow (TCPFLOW).
// TCP [[forward]] blocks multiplex over it: OPEN frames name the target, the
// exit side dials it. The lane's own udp [[forward]] stays as-is.
// ---------------------------------------------------------------------------

const OP_OPEN: u8 = 1;
const OP_DATA: u8 = 2;
const OP_ACK: u8 = 3;
const OP_FIN: u8 = 4;
const OP_RST: u8 = 5;

fn frame_open(sid: u32, target: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&sid.to_be_bytes());
    out.push(OP_OPEN);
    out.extend_from_slice(&(target.len() as u16).to_be_bytes());
    out.extend_from_slice(target.as_bytes());
}

fn frame_data(sid: u32, seq: u64, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&sid.to_be_bytes());
    out.push(OP_DATA);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

fn frame_ack(sid: u32, ack_to: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&sid.to_be_bytes());
    out.push(OP_ACK);
    out.extend_from_slice(&ack_to.to_be_bytes());
}

fn frame_fin(sid: u32, final_off: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&sid.to_be_bytes());
    out.push(OP_FIN);
    out.extend_from_slice(&final_off.to_be_bytes());
}

fn frame_rst(sid: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&sid.to_be_bytes());
    out.push(OP_RST);
}

#[derive(Debug)]
enum Op<'a> {
    Open(u32, &'a str),
    Data(u32, u64, &'a [u8]),
    Ack(u32, u64),
    Fin(u32, u64),
    Rst(u32),
}

fn parse_frame(b: &[u8]) -> Option<Op<'_>> {
    if b.len() < 5 {
        return None;
    }
    let sid = u32::from_be_bytes(b[0..4].try_into().ok()?);
    match *b.get(4)? {
        OP_OPEN => {
            let l = u16::from_be_bytes(b.get(5..7)?.try_into().ok()?) as usize;
            let t = b.get(7..7 + l)?;
            Some(Op::Open(sid, std::str::from_utf8(t).ok()?))
        }
        OP_DATA => {
            let seq = u64::from_be_bytes(b.get(5..13)?.try_into().ok()?);
            let l = u16::from_be_bytes(b.get(13..15)?.try_into().ok()?) as usize;
            let p = b.get(15..15 + l)?;
            Some(Op::Data(sid, seq, p))
        }
        OP_ACK => Some(Op::Ack(
            sid,
            u64::from_be_bytes(b.get(5..13)?.try_into().ok()?),
        )),
        OP_FIN => Some(Op::Fin(
            sid,
            u64::from_be_bytes(b.get(5..13)?.try_into().ok()?),
        )),
        OP_RST => Some(Op::Rst(sid)),
        _ => None,
    }
}

enum SinkMsg {
    Data(Vec<u8>),
    Fin,
    Rst,
}

struct InFlight {
    data: Vec<u8>,
    sent: Instant,
    retries: u8,
}

struct Snd {
    target: String,
    outq: VecDeque<Vec<u8>>,
    outq_bytes: usize,
    inflight: BTreeMap<u64, InFlight>,
    inflight_bytes: usize,
    next_seq: u64,
    peer_acked: u64,
    srtt: Option<Duration>,
    rto: Duration,
    fin_off: Option<u64>,
    fin_retries: u8,
    peer_fin_acked: bool,
    dead: bool,
}

impl Snd {
    fn new(target: String) -> Snd {
        Snd {
            target,
            outq: VecDeque::new(),
            outq_bytes: 0,
            inflight: BTreeMap::new(),
            inflight_bytes: 0,
            next_seq: 0,
            peer_acked: 0,
            srtt: None,
            rto: TCP_MIN_RTO,
            fin_off: None,
            fin_retries: 0,
            peer_fin_acked: false,
            dead: false,
        }
    }
}

struct Rcv {
    want: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    held: usize,
    fin_off: Option<u64>,
    acked_upto: u64,
    dirty: bool,
    fin_ticks: u8,
}

impl Rcv {
    fn new() -> Rcv {
        Rcv {
            want: 0,
            pending: BTreeMap::new(),
            held: 0,
            fin_off: None,
            acked_upto: 0,
            dirty: false,
            fin_ticks: 0,
        }
    }
}

struct TcpMux {
    h: Arc<Handle>,
    chunk: usize,
    next_sid: std::sync::atomic::AtomicU32,
    snd: Mutex<HashMap<u32, Snd>>,
    rcv: Mutex<HashMap<u32, Rcv>>,
    sinks: Mutex<HashMap<u32, mpsc::UnboundedSender<SinkMsg>>>,
    notify: Notify,
}

impl TcpMux {
    fn new(h: Arc<Handle>) -> TcpMux {
        let chunk = h
            .payload_mtu()
            .saturating_sub(48)
            .clamp(TCP_MIN_CHUNK, TCP_CHUNK);
        TcpMux {
            h,
            chunk,
            next_sid: std::sync::atomic::AtomicU32::new(1),
            snd: Mutex::new(HashMap::new()),
            rcv: Mutex::new(HashMap::new()),
            sinks: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        }
    }

    // ---- local-connection bridging (both roles) --------------------------

    async fn bridge_conn(
        self: &Arc<Self>,
        sid: u32,
        conn: tokio::net::TcpStream,
        target: String,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = conn.set_nodelay(true);
        let (mut r, mut w) = conn.into_split();
        let (tx, mut rx) = mpsc::unbounded::<SinkMsg>();
        self.sinks.lock().expect("sinks").insert(sid, tx);
        let snd = Snd::new(target);
        self.snd.lock().expect("snd").insert(sid, snd);
        self.rcv.lock().expect("rcv").insert(sid, Rcv::new());
        self.notify.notify_one();

        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                match m {
                    SinkMsg::Data(d) => {
                        if w.write_all(&d).await.is_err() {
                            break;
                        }
                    }
                    SinkMsg::Fin => {
                        let _ = w.shutdown().await;
                    }
                    SinkMsg::Rst => break,
                }
            }
        });

        let mux = self.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if mux.conn_send(sid, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            mux.conn_fin(sid);
        });
        tokio::spawn(async move {
            let _ = reader.await;
            writer.abort();
        });
    }

    async fn conn_send(&self, sid: u32, data: &[u8]) -> Result<()> {
        loop {
            {
                let mut snd = self.snd.lock().expect("snd");
                if let Some(s) = snd.get_mut(&sid) {
                    if s.dead {
                        bail!("stream {sid} dead");
                    }
                    if s.outq_bytes + data.len() <= TCP_WINDOW {
                        s.outq.push_back(data.to_vec());
                        s.outq_bytes += data.len();
                        self.notify.notify_one();
                        return Ok(());
                    }
                } else {
                    bail!("stream {sid} gone");
                }
            }
            self.notify.notified().await;
        }
    }

    fn conn_fin(&self, sid: u32) {
        if let Some(s) = self.snd.lock().expect("snd").get_mut(&sid) {
            if s.fin_off.is_none() {
                s.fin_off = Some(s.next_seq);
            }
        }
        self.notify.notify_one();
    }

    // ---- frames ----------------------------------------------------------

    fn on_frame(self: &Arc<Self>, b: &[u8]) {
        match parse_frame(b) {
            Some(Op::Open(sid, target)) => {
                if self.snd.lock().expect("snd").contains_key(&sid) {
                    return;
                }
                let mux = self.clone();
                let target = target.to_string();
                tokio::spawn(async move {
                    let conn = match tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(&target),
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        _ => {
                            warn!("tcp stream {sid}: connect to {target} failed");
                            let mut out = Vec::new();
                            frame_rst(sid, &mut out);
                            mux.h.send(TCPFLOW, &out);
                            return;
                        }
                    };
                    info!("tcp stream {sid}: delivering to {target}");
                    mux.bridge_conn(sid, conn, target).await;
                });
            }
            Some(Op::Data(sid, seq, payload)) => self.on_data(sid, seq, payload),
            Some(Op::Ack(sid, ack_to)) => self.on_ack(sid, ack_to),
            Some(Op::Fin(sid, off)) => self.on_fin(sid, off),
            Some(Op::Rst(sid)) => self.kill(sid, "peer reset"),
            None => {}
        }
    }

    fn on_data(&self, sid: u32, seq: u64, payload: &[u8]) {
        let sink = {
            let mut rcvs = self.rcv.lock().expect("rcv");
            let rcv = match rcvs.get_mut(&sid) {
                Some(r) => r,
                None => return,
            };
            let end = seq + payload.len() as u64;
            if end <= rcv.want {
                return;
            }
            if seq > rcv.want {
                if rcv.held + payload.len() > TCP_WINDOW {
                    return; // window full, sender retransmits
                }
                rcv.pending.insert(seq, payload.to_vec());
                rcv.held += payload.len();
                return;
            }
            // in-order delivery, then drain anything pending covers
            let n = (rcv.want - seq) as usize;
            let mut deliver: Vec<Vec<u8>> = Vec::new();
            deliver.push(payload[n..].to_vec());
            rcv.want = end;
            loop {
                let key = match rcv.pending.keys().next() {
                    Some(k) if *k == rcv.want => *k,
                    _ => break,
                };
                let d = rcv.pending.remove(&key).expect("key just peeked");
                rcv.held -= d.len();
                rcv.want += d.len() as u64;
                deliver.push(d);
            }
            rcv.dirty = true;
            if let Some(fin) = rcv.fin_off {
                if rcv.want >= fin {
                    deliver.push(Vec::new()); // marker for Fin
                }
            }
            let sink = self.sinks.lock().expect("sinks").get(&sid).cloned();
            if let Some(sink) = sink {
                for d in &deliver {
                    let _ = sink.send(SinkMsg::Data(d.clone()));
                }
                if rcv.fin_off.is_some() && rcv.want >= rcv.fin_off.unwrap() {
                    let _ = sink.send(SinkMsg::Fin);
                }
            }
            sink.is_some()
        };
        let _ = sink;
        self.notify.notify_one();
    }

    fn on_ack(&self, sid: u32, ack_to: u64) {
        let mut snds = self.snd.lock().expect("snd");
        let Some(s) = snds.get_mut(&sid) else {
            return;
        };
        if ack_to > s.peer_acked {
            let now = Instant::now();
            let newly: Vec<u64> = s
                .inflight
                .iter()
                .filter(|(off, c)| *off + c.data.len() as u64 <= ack_to)
                .map(|(off, _)| *off)
                .collect();
            // sample rtt from the newest chunk that just got fully acked
            for (i, off) in newly.iter().enumerate() {
                if let Some(c) = s.inflight.remove(off) {
                    if c.retries == 0 && i + 1 == newly.len() {
                        let rtt = now.duration_since(c.sent);
                        s.srtt = Some(match s.srtt {
                            None => rtt,
                            Some(prev) => prev / 8 + rtt / 8 * 7,
                        });
                        let base = s.srtt.unwrap();
                        s.rto = (base * 4).clamp(TCP_MIN_RTO, TCP_MAX_RTO);
                    }
                    s.inflight_bytes -= c.data.len();
                }
            }
            s.peer_acked = ack_to;
            if let Some(fin) = s.fin_off {
                if ack_to >= fin {
                    s.peer_fin_acked = true;
                }
            }
            self.notify.notify_one();
        }
    }

    fn on_fin(&self, sid: u32, off: u64) {
        let sink = {
            let mut rcvs = self.rcv.lock().expect("rcv");
            let Some(r) = rcvs.get_mut(&sid) else {
                return;
            };
            if r.fin_off.is_none() {
                r.fin_off = Some(off);
            }
            let done = r.fin_off.is_some() && r.want >= r.fin_off.unwrap();
            self.sinks
                .lock()
                .expect("sinks")
                .get(&sid)
                .cloned()
                .filter(|_| done)
        };
        if let Some(sink) = sink {
            let _ = sink.send(SinkMsg::Fin);
        }
    }

    // lock order everywhere: snd -> rcv -> sinks (prevents lock-order deadlock
    // between this and on_data, which holds rcv while touching sinks)
    fn kill(&self, sid: u32, why: &str) {
        warn!("tcp stream {sid}: {why}");
        self.snd.lock().expect("snd").remove(&sid);
        self.rcv.lock().expect("rcv").remove(&sid);
        if let Some(sink) = self.sinks.lock().expect("sinks").remove(&sid) {
            let _ = sink.send(SinkMsg::Rst);
        }
    }

    // ---- driver ----------------------------------------------------------

    async fn drive(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(TCP_TICK) => {}
                _ = self.notify.notified() => {}
            }
            let mut frames: Vec<Vec<u8>> = Vec::new();
            {
                let ids: Vec<u32> = self.snd.lock().expect("snd").keys().copied().collect();
                for sid in ids {
                    let dead = {
                        let mut snds = self.snd.lock().expect("snd");
                        let s = snds.get_mut(&sid).expect("snd entry");
                        // flush queued bytes into the window
                        while !s.outq.is_empty()
                            && s.inflight_bytes < TCP_WINDOW
                            && s.fin_off.is_none()
                        {
                            let mut chunk = s.outq.pop_front().unwrap();
                            s.outq_bytes -= chunk.len();
                            while !chunk.is_empty() {
                                let n = chunk.len().min(self.chunk);
                                let piece: Vec<u8> = chunk.drain(..n).collect();
                                let seq = s.next_seq;
                                s.next_seq += n as u64;
                                s.inflight_bytes += n;
                                let mut f = Vec::with_capacity(n + 15);
                                frame_data(sid, seq, &piece, &mut f);
                                frames.push(f);
                                s.inflight.insert(
                                    seq,
                                    InFlight {
                                        data: piece,
                                        sent: Instant::now(),
                                        retries: 0,
                                    },
                                );
                            }
                        }
                        // retransmit
                        let now = Instant::now();
                        let expired: Vec<u64> = s
                            .inflight
                            .iter()
                            .filter(|(_, c)| now.duration_since(c.sent) > s.rto)
                            .map(|(off, _)| *off)
                            .collect();
                        for off in expired {
                            if let Some(c) = s.inflight.get_mut(&off) {
                                c.retries += 1;
                                if c.retries > TCP_MAX_RETRIES {
                                    s.dead = true;
                                    break;
                                }
                                c.sent = now;
                                let mut f = Vec::with_capacity(c.data.len() + 15);
                                frame_data(sid, off, &c.data, &mut f);
                                frames.push(f);
                            }
                        }
                        // fin
                        if let Some(fin) = s.fin_off {
                            if !s.peer_fin_acked && s.inflight.is_empty() && s.outq.is_empty() {
                                if s.fin_retries <= TCP_MAX_RETRIES {
                                    s.fin_retries += 1;
                                    let mut f = Vec::with_capacity(13);
                                    frame_fin(sid, fin, &mut f);
                                    frames.push(f);
                                } else {
                                    s.peer_fin_acked = true; // peer is gone; stop trying
                                }
                            }
                        }
                        s.dead
                    };
                    if dead {
                        let mut out = Vec::new();
                        frame_rst(sid, &mut out);
                        frames.push(out);
                        self.kill(sid, "too many retransmits");
                    }
                }
            }

            {
                let mut rcvs = self.rcv.lock().expect("rcv");
                let mut reap: Vec<u32> = Vec::new();
                for (sid, r) in rcvs.iter_mut() {
                    if let Some(fin) = r.fin_off {
                        if r.want >= fin {
                            r.fin_ticks += 1;
                            if r.fin_ticks > 20 {
                                reap.push(*sid);
                                continue;
                            }
                        }
                    }
                    if r.want > r.acked_upto || !r.pending.is_empty() || r.fin_off.is_some() {
                        r.acked_upto = r.want;
                        r.dirty = false;
                        let mut f = Vec::with_capacity(13);
                        frame_ack(*sid, r.want, &mut f);
                        frames.push(f);
                    }
                }
                for sid in reap {
                    rcvs.remove(&sid);
                }
            }
            for f in frames {
                self.h.send(TCPFLOW, &f);
            }
            // reap finished senders
            {
                let done: Vec<u32> = self
                    .snd
                    .lock()
                    .expect("snd")
                    .iter()
                    .filter(|(_, s)| s.peer_fin_acked)
                    .map(|(sid, _)| *sid)
                    .collect();
                for sid in done {
                    self.snd.lock().expect("snd").remove(&sid);
                }
            }
        }
    }
}
