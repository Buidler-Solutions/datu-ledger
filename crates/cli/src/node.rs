//! `datu node`: the always-on home node - daemon-style, like running a
//! Monero node at home on a cheap computer.
//!
//! One process, no dependencies, no central server:
//! - listens on the **native p2p sync protocol** (raw TCP, no HTTP) so any
//!   node anywhere can reconcile with it,
//! - pulls from configured peers every cycle and (optionally) from peers it
//!   discovers on the LAN via mDNS,
//! - witness-checkpoints everything it has seen (`--witness`),
//! - optionally serves the HTTP explorer/API for humans and dApps
//!   (`--http`) - that frontend is a convenience, never a dependency.
//!
//! The same store also syncs with zero network at all: `datu delta` files
//! and `datu bundle` travel by USB, email, or any channel that moves bytes.

use crate::{
    effective_policy, load_node_reader, network_hello, our_network_id, pull_peer, read_network,
    short, sign_checkpoint_into,
};

/// The policy to apply *right now*: recomputed per connection and per sync
/// cycle, so a node that bootstrapped on a pinned-but-chainless mesh promotes
/// itself to the real manifest the moment the chain verifies - no restart.
fn current_policy(data_dir: &std::path::Path, read_only: bool) -> Option<datu_store::WritePolicy> {
    match effective_policy(data_dir, read_only, true) {
        Ok(p) => p,
        Err(e) => {
            println!("[governance] refusing writes: {e}");
            Some(datu_store::WritePolicy::readonly())
        }
    }
}
use datu_p2p::{handle_connection, mesh_name};
use datu_store::Store;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

/// The mDNS service type datu nodes announce and browse for.
pub const SERVICE_TYPE: &str = "_datu-sync._tcp.local.";

/// Best-effort local IP (no packet leaves the machine: connected-UDP trick).
fn local_ip() -> std::net::IpAddr {
    let guess = || -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        Some(socket.local_addr().ok()?.ip())
    };
    guess().unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}

/// Browse the LAN for datu nodes. Returns (address "ip:port", identity hex,
/// network id - "" = the open network).
pub fn discover_peers(seconds: u64) -> Result<Vec<(String, String, String)>, String> {
    let mdns = ServiceDaemon::new().map_err(|e| format!("mDNS unavailable: {e}"))?;
    let receiver = mdns.browse(SERVICE_TYPE).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(seconds.max(1));
    let mut found: Vec<(String, String, String)> = Vec::new();
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            break;
        }
        match receiver.recv_timeout(timeout) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                let identity = service
                    .get_property_val_str("identity")
                    .unwrap_or_default()
                    .to_string();
                let network = service
                    .get_property_val_str("network")
                    .unwrap_or_default()
                    .to_string();
                let mut ips: Vec<std::net::Ipv4Addr> =
                    service.get_addresses_v4().into_iter().collect();
                ips.sort();
                if let Some(ip) = ips.first() {
                    let address = format!("{ip}:{}", service.get_port());
                    if !found.iter().any(|(a, _, _)| a == &address) {
                        found.push((address, identity, network));
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break, // deadline reached or daemon gone
        }
    }
    let _ = mdns.shutdown();
    Ok(found)
}

fn announce(
    mdns: &ServiceDaemon,
    identity: &str,
    port: u16,
    network_id: &str,
) -> Result<(), String> {
    let tag = &identity[..8.min(identity.len())];
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &format!("datu-{tag}"),
        &format!("datu-{tag}.local."),
        local_ip().to_string(),
        port,
        &[("identity", identity), ("network", network_id)][..],
    )
    .map_err(|e| e.to_string())?;
    mdns.register(info).map_err(|e| e.to_string())
}

/// The `datu discover` command.
pub fn discover(seconds: u64) -> Result<(), String> {
    println!("browsing the local network for datu nodes ({seconds}s)…");
    let peers = discover_peers(seconds)?;
    if peers.is_empty() {
        println!("no nodes found on this LAN");
        println!("  a node announces itself when `datu node` is running");
        return Ok(());
    }
    for (address, identity, network) in &peers {
        println!(
            "{address:<22} {} ({}) [{}]",
            short(identity),
            identity,
            if network.is_empty() {
                "open network".to_string()
            } else {
                format!("mesh {network}")
            }
        );
    }
    println!("sync: datu sync --peer <address>   (native p2p, no HTTP involved)");
    Ok(())
}

/// The `datu node` daemon.
#[allow(clippy::too_many_arguments)]
pub fn run(
    data_dir: &Path,
    addr: &str,
    peers: Vec<String>,
    every: u64,
    discover: bool,
    witness: bool,
    http: Option<String>,
    read_only: bool,
) -> Result<(), String> {
    // A reader handle: the daemon must be able to *start* on a pinned mesh
    // whose chain it has not received yet - that is how it gets one.
    let node = load_node_reader(data_dir)?;
    // Recomputed per cycle/connection below: a node that started while pinned
    // without a chain runs a bootstrap policy (chain namespace only) and
    // promotes itself the moment the chain verifies.
    let policy = effective_policy(data_dir, read_only, true)?;
    let frozen = matches!(&policy, Some(p) if p.readonly);
    let network = read_network(data_dir)?;
    let our_id = our_network_id(data_dir)?;
    // Fail-closed: a permissioned node that could not admit itself must
    // refuse to run, not run isolated (or silently serve nobody).
    if let Some(net) = &network {
        if net.is_permissioned() && !net.self_admitted(&node.identity) {
            return Err(format!(
                "refusing to start: network.json is permissioned but this node's key {} is not a member or root - fix network.json (see `datu network show`)",
                short(&node.identity)
            ));
        }
    }
    let db = data_dir.join("node.db");
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    // Optional HTTP explorer/API - a frontend, never a sync dependency.
    if let Some(http_addr) = &http {
        let dir = data_dir.to_path_buf();
        let bind = http_addr.clone();
        let policy = policy.clone();
        std::thread::spawn(move || {
            let _ = crate::serve::serve(
                &dir,
                &bind,
                policy,
                crate::serve::DEFAULT_SUBMIT_PER_MIN,
                crate::serve::DEFAULT_HAVES_PER_MIN,
            );
        });
    }

    // Announce on the LAN so other nodes find us with zero configuration.
    let mdns = ServiceDaemon::new().ok();
    if let Some(daemon) = &mdns {
        match announce(daemon, &node.identity, port, &our_id) {
            Ok(()) => println!(
                "announcing on the LAN as datu-{} (_datu-sync._tcp)",
                short(&node.identity)
            ),
            Err(e) => println!("mDNS announce skipped: {e}"),
        }
    }

    // Native p2p listener: any node can dial us and reconcile - gated by
    // the network policy when one exists (hello handshake, mesh wall).
    {
        let db = db.clone();
        let dir = data_dir.to_path_buf();
        let network = network.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let db = db.clone();
                let dir = dir.clone();
                let network = network.clone();
                std::thread::spawn(move || {
                    let policy = current_policy(&dir, read_only);
                    if let Ok(store) = Store::open_with_policy(&db, policy) {
                        handle_connection(conn, &store, network.as_ref());
                    }
                });
            }
        });
    }

    println!("datu node {} is running", node.identity);
    println!("  native p2p sync:  {addr} (any node, any network, no HTTP)");
    println!("  configured peers: {}", peers.len());
    println!(
        "  lan discovery:    {}   witness checkpoints: {}",
        if discover { "on" } else { "off" },
        if witness { "on" } else { "off" }
    );
    match &policy {
        None => println!(
            "  writer policy:    none - free observer (accepts everything, views everything)"
        ),
        Some(p) if p.readonly => {
            println!("  writer policy:    read-only mirror (view + witness only, no new entries)")
        }
        Some(p) => println!(
            "  writer policy:    validator gate ({} trust root(s), {} writer(s), gated: {})",
            p.attestors.len(),
            p.writers.len(),
            p.gated.join(", ")
        ),
    }
    match &network {
        None => println!("  network:          open - permissionless, any node may join and sync"),
        Some(n) if n.is_permissioned() => println!(
            "  network:          permissioned mesh {} ({} member(s), {} attestation root(s)) - strangers are refused at the door",
            mesh_name(&n.network_id),
            n.members.len(),
            n.roots.len()
        ),
        Some(n) if !n.network_id.is_empty() => println!(
            "  network:          walled mesh {} (permissionless mirror - syncs only inside the wall)",
            n.network_id
        ),
        Some(_) => println!("  network:          open - permissionless, any node may join and sync"),
    }
    if let Some(http_addr) = &http {
        println!("  http explorer:    http://{http_addr}/");
    }
    println!("  offline paths:    datu delta / datu bundle (USB, email, any channel)");
    println!("ctrl-c to stop");

    if every == 0 {
        println!("auto-sync disabled (--every 0): serving only");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    let mut last_seen_count: Option<u64> = None;
    loop {
        let mut targets = peers.clone();
        if discover {
            if let Ok(found) = discover_peers(2) {
                for (address, identity, peer_network) in found {
                    let same_mesh = peer_network == our_id;
                    if !same_mesh {
                        println!(
                            "[discover] skipping {address}: on {}, we are on {}",
                            mesh_name(&peer_network),
                            mesh_name(&our_id)
                        );
                    } else if identity != node.identity && !targets.contains(&address) {
                        targets.push(address);
                    }
                }
            }
        }
        for peer in &targets {
            if frozen {
                break;
            }
            let store = Store::open_with_policy(&db, current_policy(data_dir, read_only))
                .map_err(|e| e.to_string())?;
            let hello = network_hello(data_dir, &node.key)?;
            match pull_peer(&store, peer, 500, hello.as_ref(), &our_id) {
                Ok(stats) => {
                    if stats.new_entries > 0 || stats.new_checkpoints > 0 {
                        println!(
                            "[sync] {peer}: +{} entries, +{} checkpoints",
                            stats.new_entries, stats.new_checkpoints
                        );
                    }
                    if stats.denied > 0 {
                        println!(
                            "[sync] {peer}: {} entries skipped by local policy",
                            stats.denied
                        );
                    }
                }
                Err(e) => println!("[sync] {peer}: {e}"),
            }
        }
        if witness {
            let store = Store::open_with_policy(&db, current_policy(data_dir, read_only))
                .map_err(|e| e.to_string())?;
            let count = store.entry_count().map_err(|e| e.to_string())?;
            let changed = last_seen_count.map(|c| c != count).unwrap_or(count > 0);
            if changed {
                match sign_checkpoint_into(&store, &node.key, &node.pq_key, &node.identity) {
                    Ok((id, height)) => println!(
                        "[witness] checkpoint {} (height {height}) over {count} entries",
                        hex::encode(id)
                    ),
                    Err(e) => println!("[witness] {e}"),
                }
            }
            last_seen_count = Some(count);
        }
        std::thread::sleep(Duration::from_secs(every));
    }
}
