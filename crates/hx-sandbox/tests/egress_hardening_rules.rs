//! Tripwire for `scripts/harden-sandbox-egress.sh`, the host-provisioning step that closes
//! the sandbox->far-host bridge hole (`crates/hx-sandbox/src/egress.rs` documents the hole and
//! deliberately does not close it in the runtime).
//!
//! The script is shell, so it cannot be unit-tested from Rust the way the runtime is. These
//! tests pin it from the outside instead: the portable half asserts the script text still
//! contains the exact rule fragments (a rule edited without updating this file fails here), and
//! on unix the exact half runs `--print-rules` for the sample subnet and asserts the emitted
//! lines byte for byte. On Windows there is no `sh`, so the twin pins the same twelve lines
//! through the worked example the script header is required to carry.
//!
//! No root, no network, no daemon: `--print-rules` is pure computation, and everything else
//! here is a string assertion.

/// The whole script, read at compile time. A rule fragment removed or reworded in the script
/// without a matching update here fails the tests below -- that is the point.
const SCRIPT: &str = include_str!("../../../scripts/harden-sandbox-egress.sh");

const SAMPLE_SUBNET: &str = "10.200.7.0/24";
const SAMPLE_GATEWAY: &str = "10.200.7.1";
const SAMPLE_PROXY_PORT: &str = "3128";

/// The twelve lines `--print-rules 10.200.7.0/24 3128` must emit, in firewall order: the
/// DOCKER-USER set first, then the same policy for the INPUT path (traffic a sandbox sends to
/// an address the host itself owns, like the bridge address, is delivered locally and never
/// traverses DOCKER-USER, so the forward-path rules alone would leave the measured sshd hole
/// open). ACCEPTs before DROPs; the proxy-port ACCEPT before the gateway DROP.
fn expected_sample_lines() -> [String; 12] {
    let mut out: [String; 12] = Default::default();
    let mut i = 0;
    for chain in ["DOCKER-USER", "INPUT"] {
        let rules = [
            format!(
                "-s {SAMPLE_SUBNET} -m conntrack --ctstate ESTABLISHED,RELATED \
                 -m comment --comment hx-sandbox-egress -j ACCEPT"
            ),
            format!(
                "-s {SAMPLE_SUBNET} -d {SAMPLE_GATEWAY}/32 -p tcp --dport {SAMPLE_PROXY_PORT} \
                 -m comment --comment hx-sandbox-egress -j ACCEPT"
            ),
            format!(
                "-s {SAMPLE_SUBNET} -d {SAMPLE_GATEWAY}/32 \
                 -m comment --comment hx-sandbox-egress -j DROP"
            ),
            format!(
                "-s {SAMPLE_SUBNET} -d 10.0.0.0/8 \
                 -m comment --comment hx-sandbox-egress -j DROP"
            ),
            format!(
                "-s {SAMPLE_SUBNET} -d 172.16.0.0/12 \
                 -m comment --comment hx-sandbox-egress -j DROP"
            ),
            format!(
                "-s {SAMPLE_SUBNET} -d 192.168.0.0/16 \
                 -m comment --comment hx-sandbox-egress -j DROP"
            ),
        ];
        for rule in rules {
            out[i] = format!("iptables -I {chain} {rule}");
            i += 1;
        }
    }
    out
}

#[test]
fn the_script_still_anchors_its_rules_in_the_docker_user_chain() {
    assert!(
        SCRIPT.contains("DOCKER-USER"),
        "the hardening rules must live in the DOCKER-USER chain; \
         if they moved, update this test and say where and why"
    );
}

#[test]
fn the_script_still_covers_the_host_local_input_path() {
    // The measured hole is the host's OWN bridge address (its sshd answered from inside the
    // sandbox). Packets to an address the host owns are delivered locally and traverse INPUT,
    // never DOCKER-USER, so a script with only forward-path rules would print green checks
    // while `nc -vz <bridge> 22` still connects. The INPUT mirror is load-bearing, not belt
    // and braces: removing it must redden this test.
    assert!(
        SCRIPT.contains("specs_for_chain INPUT"),
        "the INPUT mirror of the policy is gone; DOCKER-USER rules alone do not reach \
         host-owned addresses"
    );
}

#[test]
fn the_proxy_port_accept_and_the_gateway_drop_survive_any_edit() {
    // Exact template fragments, not paraphrases: rewording the ACCEPT (or softening the DROP
    // to a REJECT/LOG) without updating this file fails here.
    let accept =
        "-d $GATEWAY/32 -p tcp --dport $PROXY_PORT -m comment --comment $COMMENT -j ACCEPT";
    let drop = "-d $GATEWAY/32 -m comment --comment $COMMENT -j DROP";
    assert!(
        SCRIPT.contains(accept),
        "the ACCEPT of the proxy port on the gateway is gone or reworded:\n{accept}"
    );
    assert!(
        SCRIPT.contains(drop),
        "the DROP of the gateway on all other ports is gone or reworded:\n{drop}"
    );
}

#[test]
fn the_script_still_offers_print_check_apply_and_revert_and_refuses_without_root() {
    for flag in ["--print-rules", "--check", "--apply", "--revert"] {
        assert!(
            SCRIPT.contains(flag),
            "mode flag {flag} is gone from the script"
        );
    }
    assert!(
        SCRIPT.contains("must be run as root"),
        "apply/check/revert must refuse without root and say so clearly"
    );
}

/// The exact half: run the script's testable core and compare byte for byte. `--print-rules`
/// needs no root and touches no firewall, so this is hermetic.
#[cfg(unix)]
#[test]
fn print_rules_emits_the_exact_hardening_lines_for_the_sample_subnet() {
    let script = format!(
        "{}/../../scripts/harden-sandbox-egress.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = std::process::Command::new("sh")
        .arg(&script)
        .arg("--print-rules")
        .arg(SAMPLE_SUBNET)
        .arg(SAMPLE_PROXY_PORT)
        .output()
        .expect("--print-rules must run under sh without root");
    assert!(
        output.status.success(),
        "--print-rules exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: Vec<String> = String::from_utf8(output.stdout)
        .expect("--print-rules output must be UTF-8")
        .lines()
        .map(str::to_string)
        .collect();
    let expected: Vec<String> = expected_sample_lines().into_iter().collect();
    assert_eq!(
        printed, expected,
        "--print-rules output drifted from the pinned rules: \
         update the script and this test together, never just one"
    );
}

/// Windows has no `sh`, so the same twelve lines are pinned through the worked example the
/// script header is required to carry. Editing the rules without updating that example fails
/// here; the unix test above covers the live output.
#[cfg(windows)]
#[test]
fn the_sample_subnet_expansion_is_pinned_without_a_shell() {
    for line in expected_sample_lines() {
        let documented = format!("#   {line}");
        assert!(
            SCRIPT.contains(&documented),
            "worked example in the script header drifted from the pinned rules:\n{documented}"
        );
    }
}
