#!/bin/sh
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/koolshare/bin
export PATH
BASE=/jffs/addons/campus-login
HOOKS=/jffs/scripts
STAGE=$(pwd)
STAMP=$(date +%Y%m%d-%H%M%S)-$$
BACKUP=$BASE/backups/$STAMP
CHANGED=0
SUCCESS=0
OLD_RUNNING=0
rollback() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$SUCCESS" != 1 ] && [ "$CHANGED" = 1 ]; then
        echo 'Installation failed; restoring previous addon files and hooks.' >&2
        /bin/sh "$BASE/manager.sh" stop >/dev/null 2>&1 || :
        for name in campusctl manager.sh page.asp site.json campus_root_ca.pem; do
            if [ -f "$BACKUP/$name" ]; then cp -p "$BACKUP/$name" "$BASE/$name"; else rm -f "$BASE/$name"; fi
        done
        for name in services-start wan-start service-event; do
            if [ -f "$BACKUP/hooks/$name" ]; then cp -p "$BACKUP/hooks/$name" "$HOOKS/$name"; else rm -f "$HOOKS/$name"; fi
        done
        if [ "$OLD_RUNNING" = 1 ] && [ -f "$BASE/manager.sh" ]; then /bin/sh "$BASE/manager.sh" boot >/dev/null 2>&1 || :; fi
    fi
    exit "$result"
}
trap rollback EXIT
trap 'exit 1' HUP INT TERM
case "$(uname -m)" in armv7*) :;; *) echo 'ARMv7 is required.' >&2; exit 1;; esac
nvram get rc_support | grep -q am_addons || { echo 'This firmware does not support addon pages.' >&2; exit 1; }
chmod 700 "$STAGE/campusctl"
"$STAGE/campusctl" verify -dir "$STAGE"
"$STAGE/campusctl" check-site -dir "$STAGE"
[ ! -L "$BASE" ] || { echo 'Addon directory must not be a symlink.' >&2; exit 1; }
if [ -e "$BASE" ] && [ ! -f "$BASE/.campus-login-managed" ]; then
    echo 'An unrelated addon directory already exists; refusing to replace it.' >&2; exit 1
fi
for name in services-start wan-start service-event; do
    [ ! -L "$HOOKS/$name" ] || { echo "Hook $name is a symlink; refusing to replace it." >&2; exit 1; }
done
mkdir -p "$BASE" "$HOOKS" "$BACKUP/hooks"
chmod 700 "$BASE" "$BASE/backups" "$BACKUP" "$BACKUP/hooks"
touch "$BASE/.campus-login-managed"
for name in campusctl manager.sh page.asp site.json campus_root_ca.pem; do
    [ ! -f "$BASE/$name" ] || cp -p "$BASE/$name" "$BACKUP/$name"
done
for name in services-start wan-start service-event; do
    [ ! -f "$HOOKS/$name" ] || cp -p "$HOOKS/$name" "$BACKUP/hooks/$name"
done
if [ -f "$BASE/manager.sh" ] && /bin/sh "$BASE/manager.sh" running >/dev/null 2>&1; then
    OLD_RUNNING=1
    /bin/sh "$BASE/manager.sh" stop || { echo 'The previous addon is busy; retry shortly.' >&2; exit 1; }
fi
CHANGED=1
for name in campusctl manager.sh page.asp site.json campus_root_ca.pem; do
    cp "$STAGE/$name" "$BASE/$name.new"
    if [ "$name" = campusctl ] || [ "$name" = manager.sh ]; then chmod 700 "$BASE/$name.new"; else chmod 600 "$BASE/$name.new"; fi
    mv "$BASE/$name.new" "$BASE/$name"
done
"$BASE/campusctl" init -dir "$BASE"

install_hook() {
    name=$1
    hook=$HOOKS/$name
    if [ ! -f "$hook" ]; then printf '#!/bin/sh\n' > "$hook"; chmod 755 "$hook"; fi
    if grep -q '^# BEGIN CAMPUS_LOGIN_ADDON$' "$hook"; then return 0; fi
    tmp="$HOOKS/.$name.campus-login.tmp"
    [ ! -e "$tmp" ] && [ ! -L "$tmp" ] || return 1
    {
        head -n 1 "$hook"
        echo '# BEGIN CAMPUS_LOGIN_ADDON'
        case "$name" in
            services-start) echo '(/bin/sh /jffs/addons/campus-login/manager.sh boot) >>/tmp/campus-login-manager.log 2>&1 &';;
            wan-start) echo '(sleep 10; /bin/sh /jffs/addons/campus-login/manager.sh wake) >>/tmp/campus-login-manager.log 2>&1 &';;
            service-event) echo 'if [ "${1:-}" = restart ] && [ "${2:-}" = campuslogin ]; then (/bin/sh /jffs/addons/campus-login/manager.sh apply) >>/tmp/campus-login-manager.log 2>&1 & fi';;
        esac
        echo '# END CAMPUS_LOGIN_ADDON'
        sed '1d' "$hook"
    } > "$tmp"
    chmod 755 "$tmp"
    sh -n "$tmp"
    mv "$tmp" "$hook"
}
for name in services-start wan-start service-event; do install_hook "$name"; done
/bin/sh "$BASE/manager.sh" boot
if [ ! -f "$BASE/page-name" ]; then echo 'Could not create addon page.' >&2; exit 1; fi
page=$(cat "$BASE/page-name")
[ -f "/www/user/$page" ] && grep -q CAMPUS_LOGIN_ADDON_ID "/www/user/$page" || { echo 'Addon page is unavailable.' >&2; exit 1; }
i=0
until [ -s /www/user/campus-login-status.json ]; do
    i=$((i + 1)); [ "$i" -le 5 ] || { echo 'Addon status service did not start.' >&2; exit 1; }
    sleep 1
done
SUCCESS=1
echo "Campus login addon installed. Page: /$page"
echo 'Auto login remains disabled until configured in the router web interface.'
