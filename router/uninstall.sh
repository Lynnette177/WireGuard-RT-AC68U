#!/bin/sh
# Restore the boot hooks that existed before the first deployment.
# Keep configuration/backups so this command never destroys private keys.
set -eu
PATH=${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=/jffs/wireguard
SCRIPTS=/jffs/scripts
sh "$BASE/service.sh" stop
for h in services-start services-stop firewall-start nat-start wan-start; do
    if [ -f "$SCRIPTS/$h" ] && grep -q '^# RTAC68U-WIREGUARD-MANAGED$' "$SCRIPTS/$h"; then
        if [ -f "$SCRIPTS/$h.wireguard-original" ]; then
            mv "$SCRIPTS/$h.wireguard-original" "$SCRIPTS/$h"
        else
            rm -f "$SCRIPTS/$h"
        fi
    fi
done
echo 'WireGuard stopped and its boot/firewall hooks removed. Existing hooks were restored.'
echo 'Configuration and backups remain in /jffs/wireguard (owner-only permissions).'
