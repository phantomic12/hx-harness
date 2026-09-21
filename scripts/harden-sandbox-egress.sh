#!/bin/sh
# harden-sandbox-egress.sh -- host-provisioning step that closes the sandbox->far-host bridge hole.
#
# THE HOLE. A sandbox on an `-egress` internal network carries no *default* route, which is what
# makes the proxy sidecar the only way *to the internet* -- but "no default route" is not "no
# reachable address". The network's IPAM config still assigns a gateway, and that gateway IS the
# far host's own bridge interface on the same on-link subnet as the sandbox. On-link delivery
# needs no route at all: the container ARPs for the address and the packet is delivered. Measured
# on rainbowone, from inside a sandbox on `10.200.7.0/24`: `10.200.7.1:22` was OPEN, answering
# with the host's own sshd banner, along with 4330, 9191, 20140 and 44321-44323. Container-
# *published* ports are dropped by Docker's network isolation; host-native services are not.
#
# WHY ENFORCEMENT LIVES HOST-SIDE. Closing this needs packet-filter rules on the far host, which
# needs far-host root and has to be installed and *verified* per host. The sandbox runtime cannot
# verify a configuration outside its control -- enforcement that silently lapses when a rule is
# missing is worse than a documented hole, because the docs would still claim it. So the runtime
# (crates/hx-sandbox/src/egress.rs, src/remote.rs) deliberately does NOT close this, and this
# script is the supported way to close it: run it on each sandbox host as root, once per egress
# subnet, and re-check it after any firewall reset. A version of this belongs in host
# provisioning, not in the sandbox runtime.
#
# WHAT IT INSTALLS. For SUBNET (the egress network's CIDR, e.g. 10.200.7.0/24) and PROXY_PORT
# (the sidecar proxy port, e.g. 3128), with GATEWAY derived as the subnet's first host address
# (network address + 1, e.g. 10.200.7.1), in firewall order:
#   1. ACCEPT established/related traffic from SUBNET (return path for allowed flows).
#   2. ACCEPT SUBNET -> GATEWAY tcp PROXY_PORT (the sidecar path must survive).
#   3. DROP SUBNET -> GATEWAY on all other ports (the measured hole: sshd etc. on the bridge).
#   4. DROP SUBNET -> 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (the host's other local
#      subnets/bridge addresses, so host-native services are unreachable).
# The set is installed in TWO chains, because the two destinations take different netfilter
# paths: traffic a sandbox sends to an address the host itself owns (the bridge address and any
# other local subnet) is delivered locally and traverses the INPUT chain, while traffic the host
# forwards between networks (e.g. toward a container on another bridge) traverses FORWARD, where
# DOCKER-USER hangs. DOCKER-USER rules alone would leave the measured sshd hole open, and INPUT
# rules alone would leave the forwarded path open, so both carry the same policy. Traffic between
# containers on the SAME bridge never reaches either chain (it is switched at L2), so the
# sandbox->sidecar alias path on the internal network is unaffected by the DROPs.
#
# USAGE (SUBNET is CIDR, PROXY_PORT is 1-65535):
#   harden-sandbox-egress.sh --print-rules SUBNET PROXY_PORT   # pure: print the iptables lines,
#                                                              # one per line, in firewall order.
#                                                              # Needs no root; this is the testable core.
#   harden-sandbox-egress.sh --check SUBNET PROXY_PORT         # exit 0 when every rule is present,
#                                                              # else exit 1 listing what is missing.
#   harden-sandbox-egress.sh --apply SUBNET PROXY_PORT         # idempotent insert (safe to re-run).
#   harden-sandbox-egress.sh --revert SUBNET PROXY_PORT        # remove exactly the rules it added.
# apply/check/revert refuse to run without root and say so.
#
# --print-rules prints `iptables -I ...` lines in the order they must appear in the chain
# (firewall order: ACCEPTs before DROPs). --apply inserts them bottom-up with bare `-I` (head
# insert, no position), so the chain head ends up reading top-down exactly as printed, regardless
# of whatever else already lives in the chain. Do NOT "simplify" apply to `-A` (append): anything
# appended after a trailing RETURN never fires.
#
# VERIFY BY HAND, on the host then from inside a sandbox:
#   1. sudo ./scripts/harden-sandbox-egress.sh --check 10.200.7.0/24 3128   # exit 0
#   2. sudo iptables -S DOCKER-USER | grep hx-sandbox-egress               # the rules are there
#   3. From inside a sandbox on that subnet: nc -vz <bridge-ip> 22        # must TIME OUT
#      (before this script it connects; the proxy port stays reachable:
#      nc -vz <bridge-ip> 3128 must still connect).
# Subnet must be IPv4; IPv6 egress subnets are refused with a message rather than half-applied.
#
# Worked example (--print-rules 10.200.7.0/24 3128 must print exactly these twelve lines):
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment hx-sandbox-egress -j ACCEPT
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -d 10.200.7.1/32 -p tcp --dport 3128 -m comment --comment hx-sandbox-egress -j ACCEPT
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -d 10.200.7.1/32 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -d 10.0.0.0/8 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -d 172.16.0.0/12 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I DOCKER-USER -s 10.200.7.0/24 -d 192.168.0.0/16 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I INPUT -s 10.200.7.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment hx-sandbox-egress -j ACCEPT
#   iptables -I INPUT -s 10.200.7.0/24 -d 10.200.7.1/32 -p tcp --dport 3128 -m comment --comment hx-sandbox-egress -j ACCEPT
#   iptables -I INPUT -s 10.200.7.0/24 -d 10.200.7.1/32 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I INPUT -s 10.200.7.0/24 -d 10.0.0.0/8 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I INPUT -s 10.200.7.0/24 -d 172.16.0.0/12 -m comment --comment hx-sandbox-egress -j DROP
#   iptables -I INPUT -s 10.200.7.0/24 -d 192.168.0.0/16 -m comment --comment hx-sandbox-egress -j DROP
set -u

COMMENT="hx-sandbox-egress"
SUBNET=""
PROXY_PORT=""
GATEWAY=""

usage() {
    cat >&2 <<'EOF'
usage: harden-sandbox-egress.sh (--print-rules|--check|--apply|--revert) SUBNET PROXY_PORT
  SUBNET is the egress network's IPv4 CIDR (e.g. 10.200.7.0/24), PROXY_PORT the sidecar
  proxy port (e.g. 3128). --print-rules needs no root; the other three must run as root.
EOF
    exit 2
}

# require_root <mode>: apply/check/revert touch the live firewall, so they refuse without root.
require_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "harden-sandbox-egress: --$1 must be run as root (it reads the live firewall); rerun with sudo." >&2
        exit 4
    fi
    if ! command -v iptables >/dev/null 2>&1; then
        echo "harden-sandbox-egress: iptables not found on PATH; install it on this host first." >&2
        exit 5
    fi
}

# valid_subnet <cidr>: IPv4 CIDR with a sane prefix; sets a normalized SUBNET.
# Refuses IPv6 and junk rather than half-applying them.
valid_subnet() {
    cidr=$1
    case "$cidr" in
        *:*|*/*/*) echo "harden-sandbox-egress: refusing non-IPv4 subnet '$cidr'; this script handles IPv4 egress subnets only." >&2; return 1 ;;
    esac
    case "$cidr" in
        */*) addr=${cidr%/*}; prefix=${cidr#*/} ;;
        *) echo "harden-sandbox-egress: SUBNET must be CIDR (e.g. 10.200.7.0/24), got '$cidr'." >&2; return 1 ;;
    esac
    case "$prefix" in
        ''|*[!0-9]*) echo "harden-sandbox-egress: bad prefix in '$cidr'." >&2; return 1 ;;
    esac
    if [ "$prefix" -lt 1 ] || [ "$prefix" -gt 30 ]; then
        echo "harden-sandbox-egress: prefix /$prefix out of range 1-30 in '$cidr' (/31 and /32 have no gateway address to guard)." >&2
        return 1
    fi
    old_ifs=$IFS; IFS=.
    # Intentionally unquoted: splitting the dotted quad on IFS is the point.
    # shellcheck disable=SC2086
    set -- $addr; IFS=$old_ifs
    if [ "$#" != "4" ]; then
        echo "harden-sandbox-egress: bad IPv4 address in '$cidr'." >&2
        return 1
    fi
    norm=""
    for octet in "$1" "$2" "$3" "$4"; do
        case "$octet" in
            ''|*[!0-9]*) echo "harden-sandbox-egress: bad octet '$octet' in '$cidr'." >&2; return 1 ;;
        esac
        # dec_of, not bare arithmetic: an octet like 08 is not an octal constant, and the
        # normalized SUBNET below never carries a leading zero into iptables.
        dec=$(dec_of "$octet")
        if [ "$dec" -lt 0 ] || [ "$dec" -gt 255 ]; then
            echo "harden-sandbox-egress: octet '$octet' out of range in '$cidr'." >&2
            return 1
        fi
        norm="${norm}${norm:+.}$dec"
    done
    SUBNET="$norm/$prefix"
}

# dec_of <digits>: the decimal value of a digit string, printed to stdout. Strips
# leading zeros by hand so an octet like 08 is never read as octal and the script needs
# no base# arithmetic the leanest /bin/sh might lack.
dec_of() {
    d=$1
    while [ "${d#0}" != "$d" ] && [ -n "${d#0}" ]; do
        d=${d#0}
    done
    [ -n "$d" ] || d=0
    echo "$d"
}

# valid_port <port>: sets PROXY_PORT.
valid_port() {
    case "$1" in
        ''|*[!0-9]*) echo "harden-sandbox-egress: PROXY_PORT must be 1-65535, got '$1'." >&2; return 1 ;;
    esac
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "harden-sandbox-egress: PROXY_PORT must be 1-65535, got '$1'." >&2
        return 1
    fi
    PROXY_PORT="$1"
}

# derive_gateway: GATEWAY is the subnet's first host address (network address + 1), which is
# the bridge address Docker assigns as the IPAM gateway. Pure arithmetic, no root, no network.
derive_gateway() {
    addr=${SUBNET%/*}; prefix=${SUBNET#*/}
    old_ifs=$IFS; IFS=.
    set -- $addr; IFS=$old_ifs
    n=$((((($(dec_of "$1") * 256) + $(dec_of "$2")) * 256 + $(dec_of "$3")) * 256 + $(dec_of "$4")))
    hostbits=$((32 - prefix))
    # Zero the host bits to get the network address, then add 1 for the gateway.
    network=$((n >> hostbits << hostbits))
    gw=$((network + 1))
    GATEWAY="$(( (gw >> 24) & 255 )).$(( (gw >> 16) & 255 )).$(( (gw >> 8) & 255 )).$(( gw & 255 ))"
}

# specs_for_chain <chain>: the six rule specs (without the leading `iptables -I <chain>`)
# in firewall order: established ACCEPT, proxy-port ACCEPT, gateway DROP, private-range DROPs.
specs_for_chain() {
    chain=$1
    printf '%s\n' "$chain -s $SUBNET -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment $COMMENT -j ACCEPT"
    printf '%s\n' "$chain -s $SUBNET -d $GATEWAY/32 -p tcp --dport $PROXY_PORT -m comment --comment $COMMENT -j ACCEPT"
    printf '%s\n' "$chain -s $SUBNET -d $GATEWAY/32 -m comment --comment $COMMENT -j DROP"
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        printf '%s\n' "$chain -s $SUBNET -d $net -m comment --comment $COMMENT -j DROP"
    done
}

# all_specs: both chains' specs, DOCKER-USER first, each in firewall order.
all_specs() {
    specs_for_chain DOCKER-USER
    specs_for_chain INPUT
}

do_print_rules() {
    all_specs | while IFS= read -r line; do
        echo "iptables -I $line"
    done
}

# do_check: exit 0 when every rule is present; otherwise list exactly what is missing and exit 1.
do_check() {
    missing=0
    while IFS= read -r line; do
        chain=${line%% *}; spec=${line#* }
        # Word-split $spec on purpose: it is six-plus separate iptables arguments.
        # shellcheck disable=SC2086
        if iptables -C "$chain" $spec >/dev/null 2>&1; then
            echo "present: iptables -I $line"
        else
            echo "missing: iptables -I $line"
            missing=1
        fi
    done <<EOF
$(all_specs)
EOF
    if [ "$missing" != "0" ]; then
        echo "harden-sandbox-egress: $SUBNET port $PROXY_PORT is NOT fully hardened (see missing lines above)." >&2
        return 1
    fi
    echo "harden-sandbox-egress: $SUBNET port $PROXY_PORT is hardened (all rules present)."
}

# do_apply: idempotent insert. Each spec is skipped when already present (-C), else head-inserted
# (-I). Specs go in bottom-up so the chain head ends up in firewall (printed) order.
do_apply() {
    rev=""
    while IFS= read -r line; do
        rev="$line
$rev"
    done <<EOF
$(all_specs)
EOF
    # Drop the trailing empty line the construction above leaves, then apply head-first.
    failed=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        chain=${line%% *}; spec=${line#* }
        # shellcheck disable=SC2086
        if iptables -C "$chain" $spec >/dev/null 2>&1; then
            echo "present: iptables -I $line"
        else
            # shellcheck disable=SC2086
            if iptables -I "$chain" $spec; then
                echo "applied: iptables -I $line"
            else
                echo "FAILED: iptables -I $line" >&2
                failed=1
            fi
        fi
    done <<EOF
$rev
EOF
    if [ "$failed" != "0" ]; then
        echo "harden-sandbox-egress: some rules failed to apply; rerun --check to see what is missing." >&2
        return 1
    fi
    echo "harden-sandbox-egress: $SUBNET port $PROXY_PORT is hardened."
}

# do_revert: remove exactly the rules this script added (same specs, deleted by match, all copies).
do_revert() {
    while IFS= read -r line; do
        chain=${line%% *}; spec=${line#* }
        # shellcheck disable=SC2086
        if iptables -C "$chain" $spec >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            while iptables -C "$chain" $spec >/dev/null 2>&1; do
                # shellcheck disable=SC2086
                iptables -D "$chain" $spec || break
            done
            echo "removed: iptables -I $line"
        else
            echo "absent: iptables -I $line"
        fi
    done <<EOF
$(all_specs)
EOF
    echo "harden-sandbox-egress: reverted rules for $SUBNET port $PROXY_PORT."
}

main() {
    [ "$#" -ge 1 ] || usage
    mode=$1; shift
    case "$mode" in
        --print-rules|--check|--apply|--revert) ;;
        -h|--help|help) usage ;;
        *) echo "harden-sandbox-egress: unknown mode '$mode'." >&2; usage ;;
    esac
    [ "$#" -eq 2 ] || usage
    valid_subnet "$1" || exit 2
    valid_port "$2" || exit 2
    derive_gateway
    case "$mode" in
        --print-rules) do_print_rules ;;
        --check) require_root check; do_check ;;
        --apply) require_root apply; do_apply ;;
        --revert) require_root revert; do_revert ;;
    esac
}

main "$@"
