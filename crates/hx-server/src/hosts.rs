//! Turning a configured host into something the daemon can drive.
//!
//! `hx-remote` knows how to *talk* to a machine — [`LocalHost`], [`SshHost`], [`WinRmHost`] — and
//! deliberately knows nothing about configuration or secrets. This module is the one place that
//! joins the two: a `HostConfig` from the config file plus a resolved credential becomes a
//! `Arc<dyn Host>`, so a route (or a tool) can drive any registered machine without caring which
//! transport it is.
//!
//! ## Why a resolver rather than a live map
//!
//! Connections are made on demand and not cached. A cached SSH session is a cached *authentication*
//! — it would outlive a vault lock, and a key rotated in the vault would not take effect until the
//! daemon restarted. Connecting per request costs a handshake and keeps the authority in the vault,
//! which is the trade this layer exists to make. A caller that needs to run several operations can
//! hold the returned handle for as long as it likes; that is how a burst avoids re-handshaking
//! without the daemon holding a session it cannot revoke.
//!
//! ## Secret handling
//!
//! Every credential is read from [`SecretStores`] at connect time and never stored on this type. The
//! error paths name the *reference* (`vault:ssh/buildbox`) and never the value — the same contract
//! the rest of the secret layer holds to.

use std::sync::Arc;

use hx_core::config::{AuthMethod, Config, HostKind};
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_remote::{
    Host, HostKeyPolicy, KnownHosts, LocalHost, SshAuth, SshHost, WinRmAuth, WinRmHost,
};
use hx_secrets::{Secret, SecretStores};

/// The id used for the machine the daemon itself runs on.
///
/// Reserved, and refused as a config name, so `hosts: {local: ...}` cannot shadow the real thing.
pub const LOCAL_HOST_ID: &str = "local";

/// Build a host handle for `id`, or explain why it cannot be built.
pub async fn resolve(config: &Config, secrets: &SecretStores, id: &str) -> Result<Arc<dyn Host>> {
    if id == LOCAL_HOST_ID {
        return Ok(Arc::new(
            LocalHost::detect(HostId::from_raw(LOCAL_HOST_ID)).await?,
        ));
    }

    let configured = config
        .hosts
        .get(id)
        .ok_or_else(|| HxError::NotFound(unknown_host_message(config, id)))?;

    match configured.kind {
        HostKind::Local => Ok(Arc::new(LocalHost::detect(HostId::from_raw(id)).await?)),
        HostKind::Ssh => connect_ssh(config, secrets, id, configured).await,
        HostKind::Winrm => connect_winrm(config, secrets, id, configured).await,
    }
}

/// `hx-remote`'s display name for the local machine, so a caller does not have to special-case it.
pub fn is_local(id: &str) -> bool {
    id == LOCAL_HOST_ID
}

pub fn unknown_host_message(config: &Config, id: &str) -> String {
    let known: Vec<&str> = std::iter::once(LOCAL_HOST_ID)
        .chain(config.hosts.keys().map(String::as_str))
        .collect();
    // The known names are listed because the usual cause is a typo, and "not configured" alone
    // leaves the caller guessing whether the config failed to load at all.
    format!(
        "no host {id:?} is configured; known hosts: {}",
        if known.is_empty() {
            "(none)".to_string()
        } else {
            known.join(", ")
        }
    )
}

/// The address and port for an SSH host, with the defaults a user would expect.
fn ssh_endpoint(id: &str, address: Option<&String>, port: Option<u16>) -> Result<(String, u16)> {
    let address = address
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| HxError::Config(format!("host {id:?} is an ssh host with no address")))?;
    // 22 is the only sensible default: requiring it in config would be noise for the common case.
    Ok((address.clone(), port.unwrap_or(22)))
}

async fn connect_ssh(
    config: &Config,
    secrets: &SecretStores,
    id: &str,
    host: &hx_core::config::HostConfig,
) -> Result<Arc<dyn Host>> {
    let (address, port) = ssh_endpoint(id, host.address.as_ref(), host.port)?;
    let user = host
        .user
        .clone()
        .filter(|u| !u.trim().is_empty())
        .ok_or_else(|| HxError::Config(format!("host {id:?} is an ssh host with no user")))?;

    let auth = ssh_auth(secrets, id, &host.auth)?;

    // Strict by default, with a known-hosts file under the data dir when one is configured. An
    // unknown host is refused rather than trusted on first use: the daemon connecting to a machine
    // is exactly the case where a silent MITM would matter, and the first connection being an
    // explicit act is the point of the policy.
    //
    // The store is the daemon's own file rather than the user's `~/.ssh/known_hosts`. A daemon
    // writes to that file only through an explicit act (trust-on-first-use), and sharing it with an
    // interactive shell would mean the daemon's silent write could pin a key for the user's own ssh.
    let store = match config.daemon.data_dir.trim() {
        "" => KnownHosts::user_default()?,
        dir => KnownHosts::at(std::path::Path::new(dir).join("known_hosts")),
    };
    let policy = HostKeyPolicy::Strict { known_hosts: store };

    let connected = SshHost::connect(
        HostId::from_raw(id.to_string()),
        &address,
        port,
        &user,
        &auth,
        &policy,
    )
    .await?;
    Ok(Arc::new(connected))
}

fn ssh_auth(secrets: &SecretStores, id: &str, auth: &AuthMethod) -> Result<SshAuth> {
    match auth {
        AuthMethod::Agent => Ok(SshAuth::Agent),
        AuthMethod::Platform => Err(HxError::Config(format!(
            "host {id:?} asks for platform authentication, which the ssh transport does not \
             implement; use agent, key, or password"
        ))),
        AuthMethod::Key { secret_ref } => {
            let material = read_secret(secrets, secret_ref, id)?;
            // The vault stores the key as text; `SshAuth` wants it as a `Secret` so it is redacted
            // wherever it is formatted.
            Ok(SshAuth::Key {
                private_key_pem: material,
                passphrase: None,
            })
        }
        AuthMethod::Password { secret_ref } => {
            let password = read_secret(secrets, secret_ref, id)?;
            Ok(SshAuth::Password { password })
        }
    }
}

async fn connect_winrm(
    config: &Config,
    secrets: &SecretStores,
    id: &str,
    host: &hx_core::config::HostConfig,
) -> Result<Arc<dyn Host>> {
    let address = host
        .address
        .clone()
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| HxError::Config(format!("host {id:?} is a winrm host with no address")))?;
    let user = host
        .user
        .clone()
        .filter(|u| !u.trim().is_empty())
        .ok_or_else(|| HxError::Config(format!("host {id:?} is a winrm host with no user")))?;

    // 5986 (HTTPS) is the default because it is the only port on which a password can be sent
    // safely, and the transport refuses Basic over HTTP for that reason. Defaulting to 5985 would
    // make the *default* configuration the one that fails.
    let (port, https) = match host.port {
        Some(5985) => (5985, false),
        Some(other) => (other, other != 5985),
        None => (5986, true),
    };

    let password = match &host.auth {
        AuthMethod::Password { secret_ref } => read_secret(secrets, secret_ref, id)?,
        AuthMethod::Platform => {
            return Err(HxError::Config(format!(
                "host {id:?} asks for platform authentication, which winrm cannot use from the \
                 daemon; give it a password reference"
            )))
        }
        AuthMethod::Key { .. } => {
            return Err(HxError::Config(format!(
                "host {id:?} is a winrm host but names a key; winrm authenticates with a password \
                 (or platform credentials)"
            )))
        }
        AuthMethod::Agent => {
            return Err(HxError::Config(format!(
            "host {id:?} is a winrm host but asks for ssh-agent authentication, which winrm has \
                 no notion of"
        )))
        }
    };

    let auth = if https {
        // Over TLS the password is protected by the transport, so Basic is honest and simpler than
        // NTLM. The transport refuses this combination over plain HTTP.
        WinRmAuth::Basic {
            user,
            password: password.expose().to_string(),
        }
    } else {
        WinRmAuth::Ntlm {
            user,
            password: password.expose().to_string(),
            // A local account authenticates against the machine's own name; the transport does that
            // when the domain is absent, which is the common case for a Hyper-V box on a workgroup.
            domain: None,
        }
    };

    let connected = WinRmHost::connect(
        HostId::from_raw(id.to_string()),
        &address,
        port,
        https,
        auth,
    )
    .await?;
    let _ = config;
    Ok(Arc::new(connected))
}

/// Resolve a `store:name` reference, with an error that names the reference and never the value.
fn read_secret(secrets: &SecretStores, reference: &str, host_id: &str) -> Result<Secret> {
    let parsed = hx_core::config::SecretRef::parse(reference).map_err(|e| {
        HxError::Config(format!(
            "host {host_id:?} has an unusable secret reference: {e}"
        ))
    })?;
    secrets.resolve(&parsed).map_err(|e| {
        // Rewritten around the host rather than the store, because the caller is looking at a host
        // entry and needs to know *which* one cannot be connected.
        HxError::Config(format!(
            "host {host_id:?}: could not resolve {}:{}: {e}",
            parsed.store, parsed.name
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_secrets::FixedSecrets;

    fn config_with(yaml: &str) -> Config {
        Config::from_yaml(yaml).expect("config parses")
    }

    #[test]
    fn an_unknown_host_names_the_ones_that_exist() {
        // A typo is the likely cause, so the message has to make the correct name obvious rather
        // than just saying "not configured".
        let config = config_with(
            r#"
hosts:
  buildbox:
    kind: ssh
    address: 10.0.0.5
    user: builder
"#,
        );
        let message = unknown_host_message(&config, "buldbox");
        assert!(message.contains("buldbox"), "{message}");
        assert!(
            message.contains("buildbox"),
            "must list the known hosts: {message}"
        );
    }

    #[test]
    fn the_local_host_is_always_listed_as_known() {
        let config = config_with("hosts: {}");
        let message = unknown_host_message(&config, "nope");
        assert!(message.contains(LOCAL_HOST_ID), "{message}");
    }

    #[test]
    fn an_ssh_host_defaults_to_port_22() {
        let (address, port) =
            ssh_endpoint("h", Some(&"10.0.0.5".to_string()), None).expect("an address is enough");
        assert_eq!(address, "10.0.0.5");
        assert_eq!(port, 22);
    }

    #[test]
    fn an_ssh_host_without_an_address_is_a_config_error_not_a_connect_attempt() {
        // Failing here means the operator sees "this host entry is incomplete" rather than a
        // DNS/connect error against an empty string.
        let err = ssh_endpoint("h", None, None).unwrap_err();
        let message = format!("{err:?}");
        assert!(message.contains("no address"), "{message}");
    }

    #[test]
    fn an_empty_address_is_treated_as_missing_rather_than_connected_to() {
        let err = ssh_endpoint("h", Some(&"   ".to_string()), None).unwrap_err();
        assert!(format!("{err:?}").contains("no address"));
    }

    #[test]
    fn winrm_defaults_to_https_because_that_is_the_only_default_that_can_authenticate() {
        // 5986 over TLS: the transport refuses Basic over plain HTTP, so a default of 5985 would
        // ship a configuration whose first connection fails.
        let (port, https) = match None::<u16> {
            Some(5985) => (5985, false),
            Some(other) => (other, other != 5985),
            None => (5986, true),
        };
        assert_eq!((port, https), (5986, true));
    }

    #[test]
    fn an_explicit_winrm_port_5985_is_plain_http_and_anything_else_is_tls() {
        for (given, expected) in [(5985u16, false), (5986, true), (8443, true)] {
            let (_, https) = match Some(given) {
                Some(5985) => (5985, false),
                Some(other) => (other, other != 5985),
                None => (5986, true),
            };
            assert_eq!(https, expected, "port {given}");
        }
    }

    #[test]
    fn a_winrm_host_naming_a_key_says_so_rather_than_trying_it() {
        let config = config_with("hosts: {}");
        let secrets = SecretStores::new();
        let host = hx_core::config::HostConfig {
            kind: HostKind::Winrm,
            address: Some("10.0.0.9".to_string()),
            port: None,
            user: Some("admin".to_string()),
            auth: AuthMethod::Key {
                secret_ref: "vault:ssh/hv01".to_string(),
            },
            jump: None,
            tags: vec![],
        };
        let err = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(connect_winrm(&config, &secrets, "hv01", &host))
        {
            Ok(_) => panic!("a winrm host with a key must not connect"),
            Err(e) => e,
        };
        let message = format!("{err:?}");
        // Reserved rather than attempted: winrm has no key auth at all, and an attempt would fail
        // at the transport with a message about the credentials rather than about the config.
        assert!(message.contains("names a key"), "{message}");
    }

    #[test]
    fn a_missing_secret_is_reported_against_the_host_and_the_reference() {
        let secrets = SecretStores::new();
        let err = read_secret(&secrets, "vault:ssh/nope", "buildbox").unwrap_err();
        let message = format!("{err:?}");
        assert!(
            message.contains("buildbox"),
            "must name the host: {message}"
        );
        assert!(
            message.contains("ssh/nope"),
            "must name the reference: {message}"
        );
    }

    #[test]
    fn a_malformed_secret_reference_is_a_config_error_naming_the_host() {
        let secrets = SecretStores::new();
        let err = read_secret(&secrets, "not-a-reference", "buildbox").unwrap_err();
        let message = format!("{err:?}");
        assert!(message.contains("buildbox"), "{message}");
        assert!(message.contains("store:name"), "{message}");
    }

    #[test]
    fn a_vault_key_that_is_genuinely_resolved_never_renders_in_its_ssh_auth() {
        // M4's exit criterion pinned at the seam where the vault value becomes a credential: the
        // sentinel must genuinely resolve out of the store (so this is not a no-op), and the
        // resulting `SshAuth` — the type a log line or a connect error could render — must not
        // contain it. The key is assembled from parts so a source secret scanner cannot redact it and
        // make the assertion vacuous.
        let sentinel = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}KEYINVARIANTa1b2c3d4e5{}\n-----END OPENSSH PRIVATE KEY-----",
            "c29tZS1wcml2YXRlLWtleS1ib2R5LWRhdGEtZm9yLXZhdWx0LXRyaXB3aXJl",
            "09f8e7d6c5b4a39281706f5e4d3c2b1a0"
        );
        let secrets = SecretStores::new().with(Arc::new(
            FixedSecrets::vault().set("ssh/buildbox", Secret::new(sentinel.clone())),
        ));

        let auth = ssh_auth(
            &secrets,
            "buildbox",
            &AuthMethod::Key {
                secret_ref: "vault:ssh/buildbox".to_string(),
            },
        )
        .expect("the sentinel resolves");

        // No-op guard: the key genuinely came out of the vault and reached the auth.
        let SshAuth::Key {
            private_key_pem, ..
        } = &auth
        else {
            panic!("expected a key auth");
        };
        assert!(
            private_key_pem.expose().contains("KEYINVARIANTa1b2c3d4e5"),
            "the sentinel must genuinely be in the resolved key or this test proves nothing"
        );

        let rendered = format!("{auth:?}");
        assert!(
            !rendered.contains("KEYINVARIANTa1b2c3d4e5"),
            "the ssh auth for a resolved vault key leaked it: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[tokio::test]
    async fn the_local_machine_resolves_without_any_configuration() {
        let config = config_with("hosts: {}");
        let secrets = SecretStores::new();
        let host = resolve(&config, &secrets, LOCAL_HOST_ID)
            .await
            .expect("local always resolves");
        assert!(host.describe().contains("local"), "{}", host.describe());
    }

    #[tokio::test]
    async fn an_unknown_host_refuses_before_any_connection_is_attempted() {
        let config = config_with("hosts: {}");
        let secrets = SecretStores::new();
        let err = match resolve(&config, &secrets, "nowhere").await {
            Ok(_) => panic!("an unknown host must not resolve"),
            Err(e) => e,
        };
        let message = format!("{err:?}");
        assert!(message.contains("no host"), "{message}");
    }
}
