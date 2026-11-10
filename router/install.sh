#!/bin/sh
# Executed only by deploy.ps1 after the user enables SSH and runs it.
set -eu
umask 077
PATH=${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=/jffs/wireguard
SCRIPTS=/jffs/scripts
STAMP=$(date +%Y%m%d-%H%M%S)-$$
BACKUP=$BASE/backups/$STAMP
STAGE=$(pwd)
CHANGED=0
SUCCESS=0
OLD_RUNNING=0
NVRAM_CHANGED=0
OLD_JFFS=''
HOOKS='services-start services-stop firewall-start nat-start wan-start'

fail() { echo "Install failed: $*" >&2; exit 1; }
finish() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$SUCCESS" != 1 ] && [ "$CHANGED" = 1 ]; then
        echo 'Installation failed; restoring the previous files and hooks.' >&2
        sh "$BASE/service.sh" stop >/dev/null 2>&1 || :
        for f in wireguard-go wgctl service.sh uninstall.sh wg0.conf; do
            if [ -f "$BACKUP/$f" ]; then cp -p "$BACKUP/$f" "$BASE/$f"; else rm -f "$BASE/$f"; fi
        done
        for h in $HOOKS; do
            for suffix in '' .wireguard-original; do
                name=$h$suffix
                if [ -f "$BACKUP/hooks/$name" ]; then cp -p "$BACKUP/hooks/$name" "$SCRIPTS/$name"; else rm -f "$SCRIPTS/$name"; fi
            done
        done
        if [ "$OLD_RUNNING" = 1 ]; then sh "$BASE/service.sh" start || :; fi
        if [ "$NVRAM_CHANGED" = 1 ]; then
            if [ -n "$OLD_JFFS" ]; then nvram set "jffs2_scripts=$OLD_JFFS"; else nvram unset jffs2_scripts; fi
            nvram commit
        fi
    fi
    exit "$result"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
case "$(uname -m)" in armv7*) :;; *) fail 'This package requires ARMv7.';; esac
# Some firmware shells can execute a tool although `command -v` reports failure.
# Use harmless real operations and retain stderr for actionable error messages.
iptables -V || fail 'Cannot execute iptables -V in the SSH shell.'
nvram get lan_ifname >/dev/null || fail 'Cannot read nvram in the SSH shell.'
readlink "/proc/$$/exe" >/dev/null || fail 'Cannot execute readlink in the SSH shell.'
awk 'BEGIN { exit 0 }' </dev/null || fail 'Cannot execute awk in the SSH shell.'
grep -q '^' /proc/version || fail 'Cannot execute grep in the SSH shell.'
OLD_JFFS=$(nvram get jffs2_scripts)
chmod 700 wireguard-go wgctl service.sh
./wgctl verify -directory . || fail 'Package integrity check failed.'
chmod 600 wg0.conf
./wireguard-go --version
./wgctl validate -config ./wg0.conf -management "$(nvram get lan_ipaddr)"
./wgctl check-lan -config ./wg0.conf -management "$(nvram get lan_ipaddr)" -address "$(nvram get lan_ipaddr)" -netmask "$(nvram get lan_netmask)"
modprobe tun || fail 'Cannot load TUN.'
[ -c /dev/net/tun ] || fail 'Missing /dev/net/tun.'
mkdir -p "$BASE" "$SCRIPTS" "$BACKUP/hooks"
chmod 700 "$BASE" "$BASE/backups" "$BACKUP" "$BACKUP/hooks"
available=$(df -k /jffs | awk 'END {print $4}')
case "$available" in ''|*[!0-9]*) fail 'Cannot read JFFS free space.';; esac
[ "$available" -gt 12000 ] || fail 'At least 12 MB of free JFFS space is required.'
for f in wireguard-go wgctl service.sh uninstall.sh wg0.conf; do
    [ ! -e "$BASE/$f" ] || cp -p "$BASE/$f" "$BACKUP/$f"
done
for h in $HOOKS; do
    [ ! -L "$SCRIPTS/$h" ] || fail "Refusing to replace symlink hook: $h"
    for suffix in '' .wireguard-original; do
        name=$h$suffix
        [ ! -e "$SCRIPTS/$name" ] || cp -p "$SCRIPTS/$name" "$BACKUP/hooks/$name"
    done
    if [ -e "$SCRIPTS/$h" ] && ! grep -q '^# RTAC68U-WIREGUARD-MANAGED$' "$SCRIPTS/$h" && [ -e "$SCRIPTS/$h.wireguard-original" ]; then
        fail "Ambiguous existing backup for $h; nothing was replaced."
    fi
done
if [ -f "$BASE/service.sh" ]; then
    if sh "$BASE/service.sh" status >/dev/null 2>&1; then OLD_RUNNING=1; fi
    sh "$BASE/service.sh" stop
elif ./wgctl link-exists -interface wg0 >/dev/null 2>&1; then
    fail 'wg0 already exists. Stop the manually started instance before deploying.'
fi
CHANGED=1
for f in wireguard-go wgctl service.sh uninstall.sh wg0.conf; do
    cp "$STAGE/$f" "$BASE/$f.new"
    if [ "$f" = wg0.conf ]; then chmod 600 "$BASE/$f.new"; else chmod 700 "$BASE/$f.new"; fi
    mv "$BASE/$f.new" "$BASE/$f"
done

install_hook() {
    h=$1
    if [ -e "$SCRIPTS/$h" ] && ! grep -q '^# RTAC68U-WIREGUARD-MANAGED$' "$SCRIPTS/$h"; then
        mv "$SCRIPTS/$h" "$SCRIPTS/$h.wireguard-original"
    fi
    {
        echo '#!/bin/sh'
        echo '# RTAC68U-WIREGUARD-MANAGED'
        if [ "$h" = services-stop ]; then
            echo '/jffs/wireguard/service.sh stop >>/tmp/wireguard-rtac68u-hooks.log 2>&1'
        fi
        printf 'if [ -f /jffs/scripts/%s.wireguard-original ]; then\n' "$h"
        printf '    /bin/sh /jffs/scripts/%s.wireguard-original "$@"\n' "$h"
        echo 'fi'
        case "$h" in
            services-start) echo '( sleep 3; /jffs/wireguard/service.sh start ) >>/tmp/wireguard-rtac68u-hooks.log 2>&1 &';;
            wan-start) echo '( sleep 5; /jffs/wireguard/service.sh restart ) >>/tmp/wireguard-rtac68u-hooks.log 2>&1 &';;
            firewall-start|nat-start) echo '/jffs/wireguard/service.sh firewall >>/tmp/wireguard-rtac68u-hooks.log 2>&1';;
        esac
        echo 'exit 0'
    } > "$SCRIPTS/$h.new"
    chmod 755 "$SCRIPTS/$h.new"
    mv "$SCRIPTS/$h.new" "$SCRIPTS/$h"
}
for h in $HOOKS; do install_hook "$h"; done
# Startup hooks require this Merlin setting. Leave its previous value on errors.
sh "$BASE/service.sh" start
if [ "$OLD_JFFS" != 1 ]; then NVRAM_CHANGED=1; nvram set jffs2_scripts=1; nvram commit; fi
sh "$BASE/service.sh" status
SUCCESS=1
echo "Installed. Previous files and hooks: $BACKUP"
echo 'DNS was not modified. IPv4 AllowedIPs from the configuration are routed through wg0.'
echo 'A zero last_handshake_time_sec means the tunnel has not completed a handshake yet.'
