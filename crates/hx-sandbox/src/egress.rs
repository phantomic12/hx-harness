//! Egress allowlist enforcement.
//!
//! The property this module exists to hold: **a sandbox reaches exactly and only the hosts on its
//! egress allowlist.** That is a stronger claim than "the network is off" (`none`) and stronger
//! than "the network is on" (`bridge`, which reaches everything); it is the middle ground an
//! operator names explicitly with `egress:` in a profile, and until now it was refused because
//! nothing could keep it.
//!
//! The mechanism, and why it is a *guarantee* rather than a promise:
//!
//! 1. [`setup`] creates a user-defined Docker network with `Internal: true`. An internal network
//!    has **no gateway**, so a container attached to it cannot route a packet to anything off the
//!    network — there is literally no route. This is the same mechanism [`docker_live`] proves for
//!    `network: none`, applied to a network the sandbox *can* talk to.
//! 2. The sandbox container is created **on** that internal network (via `network_mode`), so it
//!    can reach the other endpoint and nothing else.
//! 3. A *proxy sidecar* container is started on both the internal network and the default bridge.
//!    It is the only node on the internal network with a path off it. Its job is
//!    [`hx-egress-proxy`](crate::bin), the [`egress_proxy`](crate::bin::egress_proxy)
//!    binary, which answers `CONNECT` requests only for hosts on the allowlist and answers `403`
//!    for everything else.
//! 4. The sandbox is pointed at the proxy with `HTTPS_PROXY`/`HTTP_PROXY` env vars, and
//!    (critically) **cannot bypass it**: with no gateway the only route out is through the sidecar,
//!    which is the thing enforcing the list.
//!
//! The net effect is true default-deny egress with an explicit grant. A process inside the sandbox
//! has no way to reach the internet except by asking the proxy, and the proxy admits only what the
//! allowlist names.
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
pub const PROXY_PORT: u16 = 3128;
/// The name the sidecar is known by on the internal network — a fixed, non-colliding alias the
/// sandbox can resolve without knowing the sidecar's generated container id.
pub const PROXY_ALIAS: &str = "hxproxy";
/// The default-bridge network every sandbox proxy rides on to reach the internet.
const OUTER_NETWORK: &str = "bridge";
/// The image the proxy sidecar runs. Ubuntu 24.04 is used both for the sandbox and here, so a
/// binary compiled against the same glibc the sandbox images carry loads without a version mismatch —
/// a host built against a newer glibc must not be expected to run in an older-container libc.
const PROXY_IMAGE: &str = "ubuntu:24.04";

/// What a sandbox with a non-empty allowlist owns and must tear down when it dies.
#[derive(Clone, Debug, PartialEq)]
pub struct EgressProxy {
    /// The internal-network name the sandbox is attached to and the proxy rides on.
    pub network: String,
    /// The proxy sidecar container's name.
    pub container: String,
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

    // 1. The internal network: no gateway, so no route off it. Creating it fresh per sandbox
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
            network_mode: Some(network.clone()),
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
    let _ = docker
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
        .await;

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

    Ok(EgressProxy { network, container })
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
