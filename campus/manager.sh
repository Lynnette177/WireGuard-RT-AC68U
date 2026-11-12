#!/bin/sh
set -u
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/koolshare/bin
export PATH
BASE=/jffs/addons/campus-login
CTL=$BASE/campusctl
PIDFILE=/tmp/campus-login.pid
LOCK=/tmp/campus-login-start.lock
STATUS=/www/user/campus-login-status.json

daemon_pid() {
    [ -f "$PIDFILE" ] || return 1
    PID=$(cat "$PIDFILE")
    case "$PID" in ''|*[!0-9]*) return 1;; esac
    kill -0 "$PID" 2>/dev/null || return 1
    [ "$(readlink "/proc/$PID/exe" 2>/dev/null)" = "$CTL" ]
}
start_daemon() {
    mkdir "$LOCK" 2>/dev/null || return 0
    trap 'rmdir "$LOCK" 2>/dev/null || :' EXIT
    if daemon_pid; then
        kill -HUP "$PID" 2>/dev/null || :
    else
        (
            trap '' HUP
            exec "$CTL" daemon -dir "$BASE" -status "$STATUS"
        ) </dev/null >> /tmp/campus-login.log 2>&1 &
        echo $! > "$PIDFILE"
    fi
    rmdir "$LOCK" 2>/dev/null || :
    trap - EXIT
}
mount_page() {
    [ -f /usr/sbin/helper.sh ] || return 1
    . /usr/sbin/helper.sh
    nvram get rc_support | grep -q am_addons || return 1
    mkdir -p /www/user || return 1
    page=''
    if [ -f "$BASE/page-name" ]; then
        candidate=$(cat "$BASE/page-name")
        case "$candidate" in user[0-9]*.asp)
            if [ ! -e "/www/user/$candidate" ] || grep -q CAMPUS_LOGIN_ADDON_ID "/www/user/$candidate" 2>/dev/null; then page=$candidate; fi;;
        esac
    fi
    if [ -z "$page" ]; then
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            if [ ! -e "/www/user/user$i.asp" ]; then page="user$i.asp"; break; fi
        done
    fi
    [ -n "$page" ] || return 1
    pub=$("$CTL" public-key -dir "$BASE") || return 1
    case "$pub" in *[!A-Za-z0-9+/=]*|'') return 1;; esac
    sed "s|__CAMPUS_PUBLIC_KEY__|$pub|g" "$BASE/page.asp" > "/www/user/$page.tmp" || return 1
    chmod 644 "/www/user/$page.tmp" && mv "/www/user/$page.tmp" "/www/user/$page" || return 1
    printf '%s\n' "$page" > "$BASE/page-name"
    chmod 600 "$BASE/page-name"
    if [ ! -f /tmp/menuTree.js ]; then cp /www/require/modules/menuTree.js /tmp/menuTree.js || return 1; fi
    changed=0
    if ! grep -q 'CAMPUS_LOGIN_ADDON_MENU' /tmp/menuTree.js; then
        grep -q 'url: "Tools_OtherSettings.asp", tabName:' /tmp/menuTree.js || return 1
        sed -i "/url: \"Tools_OtherSettings.asp\", tabName:/a {url: \"$page\", tabName: \"Campus Login\"}, // CAMPUS_LOGIN_ADDON_MENU" /tmp/menuTree.js || return 1
        changed=1
    fi
    if [ "$changed" = 1 ] && mount | grep -q 'on /www/require/modules/menuTree.js '; then umount /www/require/modules/menuTree.js || return 1; fi
    if ! mount | grep -q 'on /www/require/modules/menuTree.js '; then mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js || return 1; fi
}
case "${1:-}" in
    boot) mount_page || echo 'Unable to mount Campus Login page' >&2; start_daemon;;
    apply) "$CTL" apply -dir "$BASE" -status "$STATUS" && start_daemon;;
    wake) start_daemon;;
    running) daemon_pid;;
    stop)
        if daemon_pid; then
            kill "$PID" 2>/dev/null || :
            n=0
            while daemon_pid && [ "$n" -lt 30 ]; do sleep 1; n=$((n + 1)); done
            if daemon_pid; then echo 'Campus login is finishing a request; retry shortly.' >&2; exit 1; fi
        fi
        rm -f "$PIDFILE"
        ;;
    status) "$CTL" status -dir "$BASE" -status "$STATUS";;
    *) echo 'Usage: manager.sh boot|apply|wake|status' >&2; exit 2;;
esac
