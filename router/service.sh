#!/bin/sh
# RTAC68U-WIREGUARD-MANAGED
# BusyBox/POSIX sh only. No config values are evaluated as shell commands.
set -u
umask 077
PATH=${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=${WG68_BASE:-/jffs/wireguard}
STATE=${WG68_STATE:-/tmp/wireguard-rtac68u}
IFACE=wg0
MANAGEMENT=$(nvram get lan_ipaddr)
CONF=$BASE/wg0.conf
CTL=$BASE/wgctl
LOCK=$STATE/lock
mkdir -p "$STATE"
chmod 700 "$STATE"

log() { echo "wireguard-rtac68u: $*"; }
fail() { log "$*" >&2; return 1; }
owned_pid() {
    [ -f "$STATE/pid" ] || return 1
    PID=$(cat "$STATE/pid")
    case "$PID" in ''|*[!0-9]*) return 1;; esac
    kill -0 "$PID" 2>/dev/null || return 1
    [ "$(readlink "/proc/$PID/exe" 2>/dev/null)" = "$BASE/wireguard-go" ]
}
acquire() {
    n=0
    until mkdir "$LOCK" 2>/dev/null; do
        if [ -f "$LOCK/pid" ]; then
            owner=$(cat "$LOCK/pid")
            case "$owner" in ''|*[!0-9]*) owner=0;; esac
            if [ "$owner" -gt 1 ] && ! kill -0 "$owner" 2>/dev/null; then
                rm -f "$LOCK/pid"
                rmdir "$LOCK" 2>/dev/null || :
                continue
            fi
        elif [ "$n" -ge 3 ]; then
            # Recover a process killed between mkdir and writing its PID.
            rmdir "$LOCK" 2>/dev/null || :
        fi
        n=$((n + 1))
        [ "$n" -le 90 ] || { fail 'Another operation is still running.'; return 1; }
        sleep 1
    done
    echo $$ > "$LOCK/pid"
    trap 'rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null || :' EXIT
    trap 'exit 1' HUP INT TERM
}
load_plan() {
    "$CTL" plan -config "$CONF" -management "$MANAGEMENT" > "$STATE/network.env.new" || return 1
    mv "$STATE/network.env.new" "$STATE/network.env" || return 1
    . "$STATE/network.env"
}
delete_jump() {
    table=$1; parent=$2; chain=$3
    while iptables -t "$table" -D "$parent" -j "$chain" 2>/dev/null; do :; done
}
remove_firewall() {
    delete_jump filter FORWARD WG68_FWD
    delete_jump filter INPUT WG68_IN
    delete_jump nat POSTROUTING WG68_NAT
    for chain in WG68_FWD WG68_IN; do
        iptables -t filter -F "$chain" 2>/dev/null || :
        iptables -t filter -X "$chain" 2>/dev/null || :
    done
    iptables -t nat -F WG68_NAT 2>/dev/null || :
    iptables -t nat -X WG68_NAT 2>/dev/null || :
}
firewall() {
    [ -f "$STATE/ready" ] && owned_pid || return 0
    load_plan || return 1
    LAN_IF=$(nvram get lan_ifname)
    [ -n "$LAN_IF" ] || LAN_IF=br0
    LAN_IP=$(nvram get lan_ipaddr)
    LAN_MASK=$(nvram get lan_netmask)
    [ -n "$LAN_IP" ] && [ -n "$LAN_MASK" ] || { fail 'Cannot determine LAN address/netmask.'; return 1; }
    # Dedicated chains; never flush any firmware or user chain.
    for chain in WG68_FWD WG68_IN; do
        iptables -t filter -N "$chain" 2>/dev/null || :
        iptables -t filter -F "$chain" || return 1
    done
    iptables -t nat -N WG68_NAT 2>/dev/null || :
    iptables -t nat -F WG68_NAT || return 1
    # Configured AllowedIPs cover both remote LANs and routed VPN clients.
    for remote in $WG_ROUTES; do
        iptables -A WG68_FWD -i "$LAN_IF" -o "$IFACE" -d "$remote" -j ACCEPT || return 1
        iptables -A WG68_FWD -i "$IFACE" -o "$LAN_IF" -s "$remote" -d "$LAN_IP/$LAN_MASK" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT || return 1
        iptables -A WG68_FWD -i "$IFACE" -o "$LAN_IF" -s "$remote" -m state --state ESTABLISHED,RELATED -j ACCEPT || return 1
        iptables -A WG68_IN -i "$IFACE" -s "$remote" -m state --state ESTABLISHED,RELATED -j ACCEPT || return 1
        iptables -t nat -A WG68_NAT -s "$LAN_IP/$LAN_MASK" -o "$IFACE" -d "$remote" -j MASQUERADE || return 1
    done
    iptables -A WG68_FWD -i "$IFACE" -j DROP || return 1
    iptables -A WG68_IN -i "$IFACE" -j DROP || return 1
    delete_jump filter FORWARD WG68_FWD
    delete_jump filter INPUT WG68_IN
    delete_jump nat POSTROUTING WG68_NAT
    iptables -I FORWARD 1 -j WG68_FWD || return 1
    iptables -I INPUT 1 -j WG68_IN || return 1
    iptables -t nat -I POSTROUTING 1 -j WG68_NAT || return 1
}
stop_service() {
    rm -f "$STATE/ready"
    remove_firewall
    if owned_pid; then
        kill "$PID" 2>/dev/null || :
        n=0
        while owned_pid && [ "$n" -lt 10 ]; do sleep 1; n=$((n + 1)); done
        if owned_pid; then kill -9 "$PID" 2>/dev/null || :; fi
        # Closing the last nonpersistent TUN FD removes its interface/routes.
        rm -f "/var/run/wireguard/$IFACE.sock"
    fi
    rm -f "$STATE/pid" "$STATE/network.env" "$STATE/network.env.new"
    log 'Stopped. Router DNS and default gateway were not changed.'
}
start_service() {
    if owned_pid && [ -f "$STATE/ready" ]; then
        firewall || return 1
        log 'Already running.'
        return 0
    fi
    if owned_pid; then stop_service; fi
    if "$CTL" link-exists -interface "$IFACE" >/dev/null 2>&1; then
        fail 'wg0 already exists and is not owned by this deployment. Stop it before installing.'
        return 1
    fi
    load_plan || return 1
    "$CTL" check-lan -config "$CONF" -management "$MANAGEMENT" -address "$(nvram get lan_ipaddr)" -netmask "$(nvram get lan_netmask)" || return 1
    # Do not replace an existing route to a different local/remote network.
    "$CTL" route-check -config "$CONF" -management "$MANAGEMENT" || return 1
    # Probe the real binary rather than relying on firmware command -v support.
    iptables -V >/dev/null || { fail 'Cannot execute iptables -V.'; return 1; }
    modprobe tun || return 1
    [ -c /dev/net/tun ] || { fail '/dev/net/tun is unavailable.'; return 1; }
    mkdir -p /var/run/wireguard || return 1
    (
        # Ignore SSH hangup with shell builtins; minimal firmware may omit nohup.
        trap '' HUP
        GOMAXPROCS=2
        GOMEMLIMIT=64MiB
        LOG_LEVEL=error
        export GOMAXPROCS GOMEMLIMIT LOG_LEVEL
        exec "$BASE/wireguard-go" -f "$IFACE"
    ) >> "$STATE/daemon.log" 2>&1 < /dev/null &
    echo $! > "$STATE/pid"
    n=0
    until [ -S "/var/run/wireguard/$IFACE.sock" ]; do
        sleep 1
        n=$((n + 1))
        if [ "$n" -gt 15 ] || ! owned_pid; then fail 'Daemon did not create its socket. Check /tmp/wireguard-rtac68u/daemon.log.'; stop_service; return 1; fi
    done
    n=0
    until "$CTL" apply -config "$CONF" -interface "$IFACE" -management "$MANAGEMENT"; do
        n=$((n + 1))
        if [ "$n" -ge 3 ]; then stop_service; return 1; fi
        sleep 5
    done
    "$CTL" network-up -config "$CONF" -interface "$IFACE" -management "$MANAGEMENT" || { stop_service; return 1; }
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { fail 'Router IPv4 forwarding is disabled.'; stop_service; return 1; }
    touch "$STATE/ready"
    firewall || { stop_service; return 1; }
    log "Started. Configured WireGuard subnets: $WG_ROUTES. Router DNS is unchanged."
}
case "${1:-}" in
    start) acquire && start_service;;
    stop) acquire && stop_service;;
    restart) acquire && { stop_service; start_service; };;
    firewall) acquire && firewall;;
    status)
        owned_pid && [ -f "$STATE/ready" ] || { fail 'Not running.'; exit 1; }
        "$CTL" show -interface "$IFACE" || exit 1
        "$CTL" network-status -interface "$IFACE"
        ;;
    *) echo 'Usage: service.sh start|stop|restart|status|firewall' >&2; exit 2;;
esac
