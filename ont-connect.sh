#!/bin/bash
# ont-connect.sh - connect this Mac directly to the fiber ONT and test the line without
# the home router: reach the ONT's management page, get internet from the ISP like the
# router would (over the ISP's VLAN if it uses one), and start netdiag.py in a new
# terminal window.
#
# Usage: unplug the router from the ONT's LAN port, plug in the Mac, then run:
#            ./ont-connect.sh                    # asks for the ISP's internet VLAN
#            ./ont-connect.sh --vlan 7           # ISP delivers internet on VLAN 7
#            ./ont-connect.sh --no-vlan          # ISP delivers internet untagged
#            ./ont-connect.sh --ont 10.0.0.138   # ONT management address (default 192.168.100.1)
#            ./ont-connect.sh --browser          # also open the ONT web interface
#            ./ont-connect.sh -- -i 0.2          # everything after -- goes to netdiag.py run
#
# The VLAN is in your router's internet / WAN settings ("VLAN ID", "802.1Q tag").
# Works offline. Changes the Ethernet adapter's settings while running and restores
# DHCP, removes the temporary VLAN and turns Wi-Fi back on when you quit.
# Only DHCP internet is supported; with PPPoE, look at the ONT page only (--browser).

ONT_IP=192.168.100.1
VLAN=""     # empty = ask; "none" = untagged
VLAN_NAME="ont-connect-vlan"
DIR=$(cd "$(dirname "$0")" && pwd)

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[38;5;208m!\033[0m %s\n' "$*"; }
step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
ask()  { local a; read -r -p "  $1 " a; echo "$a"; }

# Wired interfaces with a cable plugged in ("status: active"), excluding Wi-Fi.
active_wired() {
    networksetup -listallhardwareports | awk '
        /^Hardware Port:/ { port = substr($0, 16) }
        /^Device:/ && port !~ /Wi-Fi|Bluetooth|Thunderbolt Bridge/ { print $2 }' |
    while read -r dev; do
        ifconfig "$dev" 2>/dev/null | grep -q "status: active" && echo "$dev"
    done
}

# Network service name (what networksetup wants) for a device like en5.
service_for() {
    networksetup -listnetworkserviceorder | awk -v dev="$1" '
        /^\([0-9*]+\)/ { name = $0; sub(/^\([0-9*]+\) /, "", name) }
        index($0, "Device: " dev ")") { print name; exit }'
}

wifi_dev() {
    networksetup -listallhardwareports | awk '/Wi-Fi/ { getline; print $2; exit }'
}

reachable() { ping -c 2 -t 2 -q "$1" >/dev/null 2>&1; }

cleanup() {
    [ -n "$CLEANED" ] && return
    CLEANED=1
    echo
    step "Restoring network settings"
    if [ -n "$ALIAS_ADDED" ]; then
        sudo ifconfig "$DEV" -alias "$MY_IP" 2>/dev/null && ok "Removed $MY_IP from $DEV"
    fi
    if [ -n "$VLAN_CREATED" ]; then
        sudo networksetup -removenetworkservice "$VLAN_NAME" >/dev/null 2>&1
        sudo networksetup -deleteVLAN "$VLAN_NAME" "$DEV" "$VLAN" >/dev/null 2>&1 &&
            ok "Temporary VLAN $VLAN removed"
    fi
    if [ -n "$CHANGED_IP" ]; then
        sudo networksetup -setdhcp "$SERVICE" && ok "\"$SERVICE\" is back on DHCP"
    fi
    if [ -n "$WIFI_WAS_ON" ]; then
        networksetup -setairportpower "$WIFI" on && ok "Wi-Fi switched back on"
    fi
    echo "  Plug the router back into the ONT. It can take a minute until it's online again."
    echo
}

# Create a temporary VLAN $VLAN on $DEV; sets VSVC/VDEV.
make_vlan() {
    sudo networksetup -createVLAN "$VLAN_NAME" "$DEV" "$VLAN" >/dev/null || return 1
    VLAN_CREATED=1
    VDEV=$(networksetup -listVLANs | awk -v n="$VLAN_NAME" '
        /User Defined Name:/ { cur = $NF }
        /Device \("Hardware" Port\):/ && cur == n { print $NF; exit }')
    [ -n "$VDEV" ] || return 1
    VSVC=$(service_for "$VDEV")
    if [ -z "$VSVC" ]; then
        sudo networksetup -createnetworkservice "$VLAN_NAME" "$VDEV" >/dev/null || return 1
        VSVC=$VLAN_NAME
    fi
    sleep 2
}

open_browser() {
    open "http://$ONT_IP"
    ok "Opened http://$ONT_IP"
    cat <<'EOF'
  Write down (read only - change nothing, especially not the LOID page!):
    • Optical Rx power   XGS-PON: -9 … -28 dBm, aim for -12 … -24
    • Optical Tx power   XGS-PON: +4 … +9 dBm
    • Error counters     FEC / BIP / HEC / CRC: note them, wait 5 min, note again
    • Uptime, temperature, model, firmware
EOF
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --vlan) VLAN=$2; shift 2 ;;
            --no-vlan) VLAN=none; shift ;;
            --ont) ONT_IP=$2; shift 2 ;;
            --browser) BROWSER=1; shift ;;
            --) shift; EXTRA="$*"; break ;;
            *) echo "usage: $0 [--vlan ID | --no-vlan] [--ont IP] [--browser] [-- netdiag options]"
               exit 1 ;;
        esac
    done
    # a free address in the ONT's /24 for this Mac (.222, or .223 if the ONT is .222)
    MY_IP="${ONT_IP%.*}.222"
    [ "$MY_IP" = "$ONT_IP" ] && MY_IP="${ONT_IP%.*}.223"
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    bold "ONT direct-connect: test the fiber line without the home router"
    if [ -z "$VLAN" ]; then
        echo "  Which VLAN does your ISP deliver internet on? It's in your router's internet /"
        echo "  WAN settings (\"VLAN ID\", \"802.1Q\"). Leave empty if there is none (untagged)."
        VLAN=$(ask "VLAN ID:")
        [ -z "$VLAN" ] && VLAN=none
    fi
    case "$VLAN" in
        none) ;;
        *[!0-9]*|"") echo "  Not a VLAN number: $VLAN"; exit 1 ;;
    esac
    echo "  Needs your admin password for changing network settings."
    sudo -v || exit 1

    step "1. Cable"
    DEV=$(active_wired | head -1)
    while [ -z "$DEV" ]; do
        warn "No Ethernet link. Unplug the router from the ONT's LAN port and plug in the Mac."
        ask "Press Enter to check again (Ctrl+C to quit)..." >/dev/null
        DEV=$(active_wired | head -1)
    done
    SERVICE=$(service_for "$DEV")
    if [ -z "$SERVICE" ]; then
        warn "Couldn't map $DEV to a network service; add the adapter in System Settings → Network."
        exit 1
    fi
    ok "Link up on $DEV (\"$SERVICE\")"

    step "2. Wi-Fi off (so all traffic goes through the ONT)"
    WIFI=$(wifi_dev)
    if [ -n "$WIFI" ] && networksetup -getairportpower "$WIFI" | grep -q "On"; then
        networksetup -setairportpower "$WIFI" off && WIFI_WAS_ON=1 && ok "Wi-Fi off (comes back on at the end)"
    else
        ok "Wi-Fi is already off"
    fi

    step "3. ONT management at $ONT_IP"
    if [ "$VLAN" = none ]; then
        # internet comes untagged on the same port: keep DHCP, add a second address for the ONT
        sudo ifconfig "$DEV" alias "$MY_IP" netmask 255.255.255.0 && ALIAS_ADDED=1
    else
        sudo networksetup -setmanual "$SERVICE" "$MY_IP" 255.255.255.0 >/dev/null && CHANGED_IP=1
    fi
    sleep 2
    if reachable "$ONT_IP"; then
        ok "ONT answers at $ONT_IP"
    else
        warn "ONT doesn't answer at $ONT_IP. Is the cable in the ONT's LAN port and the ONT powered?"
        exit 1
    fi

    if [ "$VLAN" = none ]; then
        step "4. Internet from the ISP, untagged (doing the router's job)"
        VDEV=$DEV
        sudo ipconfig set "$VDEV" DHCP
    else
        step "4. Internet over VLAN $VLAN (doing the router's job)"
        if ! make_vlan; then
            warn "Couldn't create VLAN $VLAN on $DEV (some USB adapters don't support VLANs)."
            exit 1
        fi
        ok "VLAN $VLAN on $DEV → $VDEV"
        sudo networksetup -setdhcp "$VSVC"
        sudo ipconfig set "$VDEV" DHCP
    fi
    WAN_IP=""
    for _ in $(seq 1 30); do
        WAN_IP=$(ipconfig getifaddr "$VDEV" 2>/dev/null)
        # untagged: the ONT address sits on the same adapter and doesn't count
        [ "$WAN_IP" = "$MY_IP" ] && WAN_IP=""
        case "$WAN_IP" in ""|169.254.*) sleep 1 ;; *) break ;; esac
    done
    case "$WAN_IP" in
        ""|169.254.*)
            warn "No address from the ISP after 30 s ($( [ "$VLAN" = none ] && echo untagged || echo "VLAN $VLAN"))."
            warn "If the router's internet settings use PPPoE, this script can't connect (DHCP only);"
            warn "if they use a VLAN, run again with --vlan <ID> (or --no-vlan if they don't)."
            [ -n "$BROWSER" ] && open_browser
            ask "Press Enter to restore settings..." >/dev/null
            exit 1
            ;;
    esac
    GW=$(ipconfig getoption "$VDEV" router 2>/dev/null)
    ok "Got $WAN_IP from the ISP, gateway $GW"
    ROUTE_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
    if [ "$ROUTE_IF" != "$VDEV" ]; then
        warn "Default route goes via $ROUTE_IF, not $VDEV. Disconnect other networks (VPN, other adapters)."
    fi
    if reachable 1.1.1.1; then
        ok "Internet works (1.1.1.1 answers)"
    else
        warn "1.1.1.1 doesn't answer yet; the analyzer may show 100% loss at first."
    fi

    [ -n "$BROWSER" ] && { step "ONT web interface"; open_browser; }

    step "5. Starting the analyzer in a new window"
    # Same terminal app as this one: it already has macOS' Local Network permission,
    # which the analyzer needs to reach the ONT and the ISP gateway.
    CMD="cd '$DIR' && caffeinate -i ./netdiag.py run --link ethernet --ont $ONT_IP${EXTRA:+ $EXTRA}"
    case "$TERM_PROGRAM" in
        iTerm.app)
            SCRIPT="tell application \"iTerm2\"
                        set w to (create window with default profile)
                        tell current session of w to write text \"$CMD\"
                        activate
                    end tell" ;;
        Apple_Terminal)
            SCRIPT="tell application \"Terminal\"
                        do script \"$CMD\"
                        activate
                    end tell" ;;
        *)  SCRIPT="" ;;
    esac
    if [ -n "$SCRIPT" ] && osascript -e "$SCRIPT" >/dev/null 2>&1; then
        ok "Started: $CMD"
    else
        warn "Couldn't open a new window automatically. Open a new tab in this terminal and run:"
        warn "  $CMD"
    fi
    echo "  If the ONT / ISP gateway show 100% loss there: System Settings → Privacy & Security →"
    echo "  Local Network → allow your terminal app."
    cat <<EOF

  The analyzer probes: ONT ($ONT_IP) → ISP gateway ($GW) → ISP hops → 1.1.1.1 / 8.8.8.8
  Neither the home router nor Wi-Fi is in the path now, so:
    • loss at the ONT                → cable / Ethernet adapter between Mac and ONT
    • ONT clean, loss from gateway on → fiber line / access network / hand-over to the ISP

  Let it run (10+ minutes is good), stop it with Ctrl+C in its window and keep its report.
EOF
    ask "Then press Enter HERE to restore your network settings..." >/dev/null
}

[ "${BASH_SOURCE[0]}" = "$0" ] && main "$@"
