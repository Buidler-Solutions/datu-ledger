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
    denial_reasons, effective_policy, load_node_reader, network_hello, our_network_id, pull_peer,
    read_network, short, sign_checkpoint_into,
};

/// Learned peers dialed per cycle: keeps a big table from meaning a big
/// burst of connections every `--every` seconds.
const LEARNED_PER_CYCLE: usize = 24;
/// Peer exchanges per cycle (seeds always, then the most useful pulls).
const EXCHANGES_PER_CYCLE: usize = 8;

use datu_p2p::peers::{exchange_peers, SHARE_LIMIT, SOURCE_CONFIGURED, SOURCE_MDNS, SOURCE_SEED};
use datu_p2p::{handle_connection_with_peers, mesh_name, PeerTable};
use datu_store::Store;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// The address other nodes should dial us on: a wildcard bind becomes the
/// machine's best-guess LAN IP, anything explicit is announced as given.
fn announce_addr(addr: &str) -> String {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        if socket.ip().is_unspecified() {
            return format!("{}:{}", local_ip(), socket.port());
        }
    }
    addr.to_string()
}

/// Peer exchange against an HTTP peer (`http://…` seeds): the same question
/// over the explorer's `/v1/peers` endpoint instead of the native wire.
fn exchange_http(
    peer: &str,
    table: &PeerTable,
    node_key: &str,
    our_mesh: &str,
    announce: &str,
    own: &[String],
) {
    let base = peer.trim().trim_end_matches('/');
    let path = format!("/v1/peers?announce={announce}&key={node_key}&network={our_mesh}");
    match crate::http_get_json(base, &path) {
        Ok(response) => {
            let wires: Vec<datu_p2p::PeerWire> = response["peers"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(|p| {
                            Some(datu_p2p::PeerWire {
                                addr: p["addr"].as_str()?.to_string(),
                                node_key: p["node_key"].as_str().unwrap_or("").to_string(),
                                network_id: p["network_id"].as_str().unwrap_or("").to_string(),
                                last_success_ms: p["last_success_ms"].as_u64().unwrap_or(0),
                            })
                        })
                        .filter(|p| !own.contains(&p.addr))
                        .collect()
                })
                .unwrap_or_default();
            let learned = table.merge_pex(&wires, our_mesh);
            if learned > 0 {
                println!("[peers] {peer}: learned {learned} address(es)");
            }
        }
        Err(e) => {
            if !e.contains("cannot connect") {
                println!("[peers] {peer}: {e}");
            }
        }
    }
}

/// The `datu node` daemon.
#[allow(clippy::too_many_arguments)]
pub fn run(
    data_dir: &Path,
    addr: &str,
    peers: Vec<String>,
    seeds: Vec<String>,
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

    // The peer table: every node this one knows about, persisted between
    // runs. Seeds grow it (peer exchange), the loop dials it, the explorer
    // shows it. One table shared by daemon, p2p listener and HTTP API.
    let table = Arc::new(PeerTable::load(data_dir));
    for peer in &peers {
        table.upsert(peer, "", &our_id, SOURCE_CONFIGURED);
    }
    for seed in &seeds {
        table.upsert(seed, "", &our_id, SOURCE_SEED);
    }
    let our_announce = announce_addr(addr);

    // Optional HTTP explorer/API - a frontend, never a sync dependency.
    if let Some(http_addr) = &http {
        let dir = data_dir.to_path_buf();
        let bind = http_addr.clone();
        let policy = policy.clone();
        let peers_api = table.clone();
        std::thread::spawn(move || {
            let _ = crate::serve::serve(
                &dir,
                &bind,
                policy,
                crate::serve::DEFAULT_SUBMIT_PER_MIN,
                crate::serve::DEFAULT_HAVES_PER_MIN,
                Some(peers_api),
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
        let table = table.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let db = db.clone();
                let dir = dir.clone();
                let network = network.clone();
                let table = table.clone();
                std::thread::spawn(move || {
                    let policy = current_policy(&dir, read_only);
                    if let Ok(store) = Store::open_with_policy(&db, policy) {
                        handle_connection_with_peers(
                            conn,
                            &store,
                            network.as_ref(),
                            Some(&table),
                            datu_p2p::PULL_PAGES_PER_CONN,
                        );
                    }
                });
            }
        });
    }

    println!("datu node {} is running", node.identity);
    println!("  native p2p sync:  {addr} (any node, any network, no HTTP)");
    println!("  configured peers: {}", peers.len());
    if !seeds.is_empty() {
        println!(
            "  seed peers:       {} + peer exchange (learns the rest of the mesh)",
            seeds.len()
        );
    }
    println!(
        "  peer table:       {} known ({} synced, persisted)",
        table.len(),
        table.count_with_success()
    );
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
        println!("    ecosystem view: http://{http_addr}/ (ecosphere tab - every entry a node in the mesh)");
        println!("    note: one explorer per deployment is enough - peers and validators can run p2p-only");
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
        targets.extend(seeds.iter().cloned());
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
                    } else {
                        table.upsert(&address, &identity, &peer_network, SOURCE_MDNS);
                        if identity != node.identity && !targets.contains(&address) {
                            targets.push(address);
                        }
                    }
                }
            }
        }
        // The learned crowd: everything peer exchange and mDNS ever told us
        // about, oldest attempt first, bounded per cycle.
        let learned = table.candidates(&our_id, &targets, LEARNED_PER_CYCLE);
        targets.extend(learned);
        let mut synced: Vec<String> = Vec::new();
        for peer in &targets {
            if frozen {
                break;
            }
            let store = Store::open_with_policy(&db, current_policy(data_dir, read_only))
                .map_err(|e| e.to_string())?;
            let hello = network_hello(data_dir, &node.key)?;
            table.record_attempt(peer);
            match pull_peer(&store, peer, 500, hello.as_ref(), &our_id) {
                Ok(stats) => {
                    table.record_success(peer, "", &our_id);
                    synced.push(peer.clone());
                    if stats.new_entries > 0 || stats.new_checkpoints > 0 {
                        println!(
                            "[sync] {peer}: +{} entries, +{} checkpoints",
                            stats.new_entries, stats.new_checkpoints
                        );
                    }
                    if stats.denied > 0 {
                        println!(
                            "[sync] {peer}: {} entries skipped by local policy{}",
                            stats.denied,
                            denial_reasons(&stats.denials)
                        );
                    }
                }
                Err(e) => {
                    table.record_failure(peer, &e);
                    if !e.contains("cannot connect") || !seeds.is_empty() {
                        println!("[sync] {peer}: {e}");
                    }
                }
            }
        }
        // Peer exchange: seeds first, then this cycle's successful pulls -
        // each answer grows the table for the next round.
        if frozen {
            table.save();
            std::thread::sleep(Duration::from_secs(every));
            continue;
        }
        let ask: Vec<String> = seeds
            .iter()
            .cloned()
            .chain(synced.iter().filter(|p| !seeds.contains(p)).cloned())
            .take(seeds.len() + EXCHANGES_PER_CYCLE)
            .collect();
        let hello = network_hello(data_dir, &node.key)?;
        // Whatever this node is dialable as: never learn ourselves back.
        let own = vec![our_announce.clone(), addr.to_string()];
        for peer in &ask {
            if peer.starts_with("http://") {
                exchange_http(peer, &table, &node.identity, &our_id, &our_announce, &own);
                continue;
            }
            let peer_addr = peer
                .strip_prefix("datu://")
                .or_else(|| peer.strip_prefix("dag://"))
                .unwrap_or(peer);
            match exchange_peers(
                peer_addr,
                hello.as_ref(),
                &node.identity,
                &our_id,
                Some(&our_announce),
                SHARE_LIMIT as u16,
            ) {
                Ok(response) => {
                    let theirs: Vec<datu_p2p::PeerWire> = response
                        .peers
                        .iter()
                        .filter(|p| !own.contains(&p.addr))
                        .cloned()
                        .collect();
                    let learned = table.merge_pex(&theirs, &our_id);
                    if learned > 0 {
                        println!("[peers] {peer}: learned {learned} address(es)");
                    }
                }
                Err(e) => {
                    // Older peers do not speak the exchange; not news.
                    if !e.contains("does not speak peer exchange")
                        && !e.contains("unknown frame")
                        && !e.contains("cannot connect")
                    {
                        println!("[peers] {peer}: {e}");
                    }
                }
            }
        }
        table.prune();
        table.save();
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
