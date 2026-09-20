//! Egress allowlist enforcement.
//!
//! The property this module exists to hold: **a sandbox reaches exactly and only the hosts on its
//! egress allowlist.** That is a stronger claim than "the network is off" (`none`) and stronger
//! than "the network is on" (`bridge`, which reaches everything); it is the middle ground an
//! operator names explicitly with `egress:` in a profile, and until now it was refused because
//! nothing could keep it.
//!
//! The mechanism, and what it actually guarantees:
//!
//! 1. [`setup`] creates a user-defined Docker network with `Internal: true`. A container attached
//!    to it gets **no default route**, so it cannot route a packet to anything off the network —
//!    there is no route for it to take. This is the same mechanism [`docker_live`] proves for
//!    `network: none`, applied to a network the sandbox *can* talk to.
//! 2. The sandbox container is created **on** that internal network (via `network_mode`), so it
//!    can reach the other endpoint and nothing else *off-network*.
//! 3. A *proxy sidecar* container is started on both the internal network and the default bridge.
//!    It is the only node on the internal network with a path off it. Its job is
//!    [`hx-egress-proxy`](crate::bin), the [`egress_proxy`](crate::bin::egress_proxy)
//!    binary, which answers `CONNECT` requests only for hosts on the allowlist and answers `403`
//!    for everything else.
//! 4. The sandbox is pointed at the proxy with `HTTPS_PROXY`/`HTTP_PROXY` env vars, and it
//!    **cannot reach the internet any other way**: with no default route there is no route out, so
//!    the sidecar is the only exit and it is the thing enforcing the list.
//!
//! The net effect is default-deny **internet** egress with an explicit grant. A process inside the
//! sandbox has no way to reach the internet except by asking the proxy, and the proxy admits only
//! what the allowlist names.
//!
//! ## The claim that used to stand here, and why it was wrong
//!
//! This module used to say the sandbox "**cannot bypass it**: with no gateway the only route out is
//! through the sidecar", and that "a container attached to it cannot route a packet to anything off
//! the network — there is literally no route". **That was false, and it was measured false.** No
//! default route is not the same thing as no reachable address: an internal network's IPAM config
//! still assigns a gateway, and that gateway is the **far host's own bridge interface on the same
//! on-link subnet as the sandbox**. On-link delivery needs no route at all — the container ARPs for
//! the address and the packet is delivered — so the host's own listening services are reachable from
//! inside the sandbox.
//!
//! Measured on rainbowone, from inside a sandbox on its own `-egress` internal network
//! (`10.200.7.0/24`, gateway `10.200.7.1`): `gateway:22` was **OPEN**, with a banner matching the
//! host's own `127.0.0.1:22`, along with `4330`, `9191`, `20140` and `44321-44323`.
//! Container-*published* ports are dropped by Docker's network isolation; **host-native services are
//! not.** The internet half of the old claim is true and stays true: `1.1.1.1:443` answers
//! `Network is unreachable`, and `/proc/net/route` inside the sandbox holds exactly one route — the
//! on-link subnet — with no `00000000` default.
//!
//! So the honest statement is: **no *internet* route except the sidecar; the far host's own bridge
//! address remains reachable from inside the sandbox.** That is a known hole. It is pinned by
//! `a_sandbox_reaches_the_far_hosts_own_bridge_address_and_that_is_a_known_hole` in
//! `crates/hx-sandbox/tests/remote_live.rs`, so it stays *known* rather than assumed, and it is
//! filed as an open security item in `ROADMAP.md`. **Do not "fix" this text back to the stronger
//! claim** — the stronger claim was the defect.
//!
//! The two ways to close it, and why neither is taken here: a `DOCKER-USER` rule on the far host
//! needs far-host root and has to be installed per host (so the module would depend on a
//! configuration it cannot verify); running the sandbox with a network namespace it controls itself
//! is the privileged route, and it would weaken the isolation this module exists to provide. Both are
//! recorded in `ROADMAP.md` rather than half-done here.
//!
//! ## What is deliberately NOT enforced here
//!
//! The allowlist is owner by hostname/`*.domain`. A raw IP or CIDR entry cannot be matched
//! against an unresolved `CONNECT` target, so such an entry is refused by
//! [`crate::spec::SandboxSpec::validate`] (`SpecError::EgressNotEnforced`) rather than
//! silently accepted — that case genuinely remains unenforceable through this mechanism, and accepting it
//! would be the exact fiction this module exists to prevent.
//!
//! Teardown is the caller's responsibility via [`teardown`]; a proxy or network left behind when
//! its sandbox dies is an orphan that still permits the (now absent) sandbox's traffic, which is
//! harmless but sloppy, so [`crate::docker::DockerRuntime`] calls it from `remove`.

use bollard::models::{ContainerCreateBody, HostConfig, NetworkConnectRequest};
use bollard::query_parameters::{
    CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::Docker;
use hx_core::error::{HxError, Result};

/// The port the proxy listens on inside its sidecar, on the internal network.
///
/// 3128 is the conventional proxy port, and it has to stay in step with the proxy binary's
/// `LISTEN_ADDR`. A mismatch would leave the sandbox holding a proxy variable that points at nothing,
/// which surfaces inside the sandbox as a connection error rather than as anything naming the cause.
pub const PROXY_PORT: u16 = 3128;
/// The name the sidecar is known by on the internal network — a fixed, non-colliding alias the
/// sandbox can resolve without knowing the sidecar's generated container id.
pub const PROXY_ALIAS: &str = "hxproxy";

/// The default-bridge network every sandbox proxy rides on to reach the internet.
const OUTER_NETWORK: &str = "bridge";
/// The image the proxy sidecar runs. Ubuntu 24.04 is used both for the sandbox and here, so a
/// binary compiled against the same glibc the sandbox images carry loads without a version mismatch —
/// a host built against a newer glibc must not be expected to run in an older-container libc.
pub const PROXY_IMAGE: &str = "ubuntu:24.04";

/// What a sandbox with a non-empty allowlist owns and must tear down when it dies.
#[derive(Clone, Debug, PartialEq)]
pub struct EgressProxy {
    /// The internal-network name the sandbox is attached to and the proxy rides on.
    pub network: String,
    /// The proxy sidecar container's name.
    pub container: String,
    /// `host:port` of the proxy as seen *from the sandbox*, i.e. by its network alias.
    ///
    /// Not the container name and not an IP: the alias is stable across restarts of the sidecar,
    /// which the container name would not be, and an IP would change with the network.
    pub endpoint: String,
}

impl EgressProxy {
    /// The proxy URL to hand a tool inside the sandbox.
    pub fn url(&self) -> String {
        format!("http://{}", self.endpoint)
    }
}

/// Create the internal network and the proxy sidecar for one sandbox.
///
/// `name_base` is the sandbox's own container name; it namespaces the resources so they are
/// greppable (`docker network ls | grep hx-<id>-egress`) and collide-free across sandboxes.
/// `proxy_bin` is the host path of the compiled [`hx-egress-proxy`](crate::bin) binary,
/// bind-mounted into the sidecar so the image needs only a libc that can load it.
pub async fn setup(
    docker: &Docker,
    name_base: &str,
    allowlist: &[String],
    proxy_bin: &std::path::Path,
) -> Result<EgressProxy> {
    let network = format!("{name_base}-egress");
    let container = format!("{name_base}-egress-proxy");

    // 1. The internal network: no *default* route, so nothing off it is routable. (It is not
    //    unreachable in every direction — the gateway address is the host's own bridge interface on
    //    the same on-link subnet, and that stays reachable; see this module's doc, which records the
    //    measurement and the ROADMAP's open security item.) Creating it fresh per sandbox
    //    (rather than sharing one) keeps one sandbox's proxy and allowlist from ever becoming another
    //    sandbox's route — each sandbox owns its enforcement, which is the only way the allowlist
    //    stays the sandbox's own reviewed guarantee.
    docker
        .create_network(bollard::models::NetworkCreateRequest {
            name: network.clone(),
            internal: Some(true),
            attachable: Some(false),
            ..Default::default()
        })
        .await
        .map_err(|e| {
            HxError::Sandbox(format!(
                "could not create the egress internal network '{network}': {e}"
            ))
        })?;

    // 2. The proxy sidecar: on the internal network (so the sandbox can reach it) and the
    //    bridge (so it can reach the internet). It runs for the lifetime of the sandbox. The
    //    allowlist is passed by environment so the proxy itself has no other source of truth for it.
    let allow_env = allowlist.join(",");
    let proxy_bin = proxy_bin
        .canonicalize()
        .map_err(|e| HxError::Sandbox(format!("proxy binary is not readable: {e}")))?;
    let body = ContainerCreateBody {
        image: Some(PROXY_IMAGE.to_string()),
        cmd: Some(vec!["/hx-egress-proxy".to_string()]),
        env: Some(vec![format!("HX_EGRESS_ALLOW={allow_env}")]),
        host_config: Some(HostConfig {
            // `network_mode` is deliberately left unset — and it must not be set to `"none"`
            // either. Docker refuses to connect a container to a user network once its network
            // mode is fixed, with "container cannot be connected to multiple networks with one of
            // the networks in private (none) mode"; the sidecar then sits on no useful network,
            // never registers its alias, and the sandbox's `HTTP_PROXY` names a host that does not
            // resolve. Omitting the field lets the default (bridge) apply, after which both
            // networks are joined below.
            // Mount the proxy binary at a fixed path. Read-only-visible in the container; it is
            // the enforcement code, so the sandbox (which shares no mounts with the sidecar anyway)
            // must never be able to modify it.
            binds: Some(vec![format!("{}:/hx-egress-proxy:ro", proxy_bin.display())]),
            ..Default::default()
        }),
        ..Default::default()
    };
    if let Err(e) = docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(container.clone()),
                ..Default::default()
            }),
            body,
        )
        .await
    {
        let _ = docker.remove_network(&network).await;
        return Err(HxError::Sandbox(format!(
            "could not create the egress proxy '{container}': {e}"
        )));
    }

    // Connect the sidecar to the outer network so it has a way off the internal one. This is
    // the single foot the sidecar holds outside; without it, the proxy could not reach the
    // internet and the sandbox would have egress to nothing.
    if let Err(e) = docker
        .connect_network(
            OUTER_NETWORK,
            NetworkConnectRequest {
                container: container.clone(),
                endpoint_config: None,
            },
        )
        .await
    {
        let _ = docker
            .remove_container(
                container.as_str(),
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        let _ = docker.remove_network(&network).await;
        return Err(HxError::Sandbox(format!(
            "the egress proxy '{container}' could not reach the outer network: {e}"
        )));
    }

    // Alias the sidecar on the internal network so the sandbox can resolve it as `PROXY_ALIAS`
    // without knowing the generated container id.
    //
    // The error is *not* discarded. An unaliased sidecar is unreachable by name, so the sandbox's
    // `HTTP_PROXY` points at nothing and every tool inside it fails to connect — a total egress
    // outage whose cause is a swallowed error 40 lines away. Failing the create names it instead.
    if let Err(e) = docker
        .connect_network(
            &network,
            NetworkConnectRequest {
                container: container.clone(),
                endpoint_config: Some(bollard::models::EndpointSettings {
                    aliases: Some(vec![PROXY_ALIAS.to_string()]),
                    ..Default::default()
                }),
            },
        )
        .await
    {
        let _ = docker
            .remove_container(
                container.as_str(),
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        let _ = docker.remove_network(&network).await;
        return Err(HxError::Sandbox(format!(
            "the egress proxy '{container}' could not be aliased as '{PROXY_ALIAS}' on \
             '{network}': {e}"
        )));
    }

    // 3. Start the proxy. It needs to be up before the sandbox is attached, or the sandbox's
    //    first request races a not-yet-listening socket.
    if let Err(e) = docker
        .start_container(&container, None::<StartContainerOptions>)
        .await
    {
        let _ = docker
            .remove_container(
                container.as_str(),
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        let _ = docker.remove_network(&network).await;
        return Err(HxError::Sandbox(format!(
            "the egress proxy '{container}' failed to start: {e}"
        )));
    }

    Ok(EgressProxy {
        network,
        container,
        endpoint: format!("{PROXY_ALIAS}:{PROXY_PORT}"),
    })
}

/// Remove the proxy sidecar and the internal network for a sandbox.
///
/// Idempotent: the container and network may already be gone (a `docker` cleanup or a crashed
/// daemon), and that is not an error here — the caller means "make sure egress enforcement for this
/// sandbox is torn down".
pub async fn teardown(docker: &Docker, proxy: &EgressProxy) {
    // `force` so a running proxy cannot keep its network alive and leak it.
    let _ = docker
        .remove_container(
            &proxy.container,
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        )
        .await;
    // The network outlives only its last container; removing it after the sidecar is gone is what
    // actually frees it.
    let _ = docker.remove_network(&proxy.network).await;
}
