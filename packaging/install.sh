#!/bin/bash
#
# install.sh — one-line installer for nginx-geosite (cddeppe nginx fork)
#
# Usage (as root or via sudo):
#   curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash
#
# Or with options:
#   curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash -s -- --start
#
# What it does:
#   1. Detects architecture (amd64 or arm64)
#   2. Fetches the latest release .deb from GitHub
#   3. apt install -y ./nginx-geosite-*.deb (replaces stock nginx if present)
#   4. Downloads geosite dlc.dat to /usr/local/etc/xray/domains/
#   5. Sets up weekly cron auto-refresh of dlc.dat
#   6. Enables nginx.service (does NOT start it by default — config may need editing)
#   7. Prints next steps
#
# Flags:
#   --start       Also start nginx after install (skips the "edit config first" gate)
#   --uninstall   Remove nginx-geosite cleanly
#   --help        Show this help
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_REPO="cddeppe/nginx"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
GEOSITE_URL="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
GEOSITE_PATH="/usr/local/etc/xray/domains/dlc.dat"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo -e "\033[1;34m==>\033[0m $*" >&2; }
warn() { echo -e "\033[1;33mWARN:\033[0m $*" >&2; }
err()  { echo -e "\033[1;31mERROR:\033[0m $*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi
}

# Detect and recover from a half-configured dpkg state (e.g. previous install
# aborted by a conffile prompt). Safe to call repeatedly.
repair_dpkg_state() {
    # Check if any package is in a half-configured/half-installed state
    # Status codes: iF=half-conf, iU=unpacked, iH=half-inst, iW=awaiting trigger,
    #               iT=trigger-pending, trig=trigger-awaiting
    local broken
    broken=$(dpkg -l 2>/dev/null | awk '/^[a-z][a-zA-Z]/ {print $1}' | grep -cE '^(iF|iU|iH|iW|iT)$' || echo 0)

    if [[ "$broken" -gt 0 ]]; then
        log "Detected $broken half-configured package(s) — repairing dpkg state"
        # dpkg --configure needs --force-confold directly (not via -o Dpkg::Options)
        DEBIAN_FRONTEND=noninteractive dpkg --configure -a --force-confold --force-confdef 2>&1 | tail -5 || true
    fi
}

# Write an apt config snippet that forces --force-confold globally for the
# duration of the install. This ensures EVERY dpkg invocation (whether from
# apt-get install, dpkg --configure, or postinst scripts) keeps the existing
# conffile instead of prompting. Removed at the end of the install.
force_confold_setup() {
    mkdir -p /etc/apt/apt.conf.d
    cat > /etc/apt/apt.conf.d/99nginx-geosite-install <<'CONF'
Dpkg::Options {
    "--force-confold";
    "--force-confdef";
};
APT::Get::Assume-Yes "true";
CONF
}

force_confold_cleanup() {
    rm -f /etc/apt/apt.conf.d/99nginx-geosite-install
}

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             die "Unsupported architecture: $machine (only amd64 and arm64 are supported)" ;;
    esac
}

detect_distro() {
    if [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/os-release ]] && grep -q '^ID_LIKE=.*debian' /etc/os-release 2>/dev/null; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------

install_deps() {
    log "Installing runtime dependencies"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        libpcre2-8-0 libssl3t64 2>/dev/null \
        || apt-get install -y --no-install-recommends libpcre2-8-0 libssl3
    # wget + curl + ca-certificates are usually present; ensure they are
    apt-get install -y --no-install-recommends wget curl ca-certificates \
        libcap2-bin adduser 2>/dev/null || true
}

download_latest_deb() {
    local arch="$1"
    local out_dir="$2"
    log "Fetching latest release info from GitHub"

    local release_json deb_url

    # Try authenticated first (if GH_TOKEN is set in env), then unauthenticated.
    # Unauthenticated calls are rate-limited to 60/hour per IP — usually fine
    # for end users, but a CI runner sharing an IP could hit the limit.
    if [[ -n "${GH_TOKEN:-}" ]]; then
        release_json="$(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" "$GITHUB_API")"
    else
        release_json="$(curl -fsSL "$GITHUB_API" 2>/dev/null || true)"
    fi

    if [[ -z "$release_json" ]]; then
        # Fallback: try to derive the URL from the latest tag without API.
        # This works because GitHub release asset URLs follow a predictable pattern:
        #   https://github.com/<repo>/releases/download/<tag>/<asset_name>
        # We scrape the latest tag from the HTML page (no rate limit on HTML).
        warn "GitHub API call failed (rate-limited?), trying HTML scrape fallback"
        local latest_tag
        latest_tag="$(curl -fsSL "https://github.com/$GITHUB_REPO/releases/latest" \
                       -o /dev/null -w '%{url_effective}' | \
                       sed 's|.*/tag/||; s|%2B|+|g')"
        if [[ -z "$latest_tag" || "$latest_tag" == "https://github.com/$GITHUB_REPO/releases" ]]; then
            die "Could not determine latest release tag. Check https://github.com/$GITHUB_REPO/releases"
        fi
        log "Latest tag (via HTML): $latest_tag"
        deb_url="https://github.com/$GITHUB_REPO/releases/download/$latest_tag/nginx-geosite_${latest_tag#v}_${arch}.deb"
    else
        # Extract .deb URL for this arch from the JSON.
        # The URL contains URL-encoded '+' as '%2B' — keep it as-is, wget handles it.
        deb_url="$(echo "$release_json" | grep -oE "https://[^\"]*_${arch}\.deb" | head -1)"
        if [[ -z "$deb_url" ]]; then
            die "No .deb found for arch=$arch in latest release. Check https://github.com/$GITHUB_REPO/releases"
        fi
    fi

    local deb_name
    deb_name="$(basename "$deb_url")"
    # Decode %2B → + for the local filename (cosmetic)
    deb_name="${deb_name//%2B/+}"
    log "Downloading $deb_name"
    wget -q -O "$out_dir/$deb_name" "$deb_url" || \
        die "Failed to download $deb_url"
    echo "$out_dir/$deb_name"
}

install_deb() {
    local deb_path="$1"
    log "Installing $deb_path (this replaces any stock nginx)"
    # apt install resolves dependencies and handles Conflicts/Replaces properly.
    # force_confold_setup() already wrote /etc/apt/apt.conf.d/99nginx-geosite-install
    # which forces --force-confold globally, so this apt-get install is fully
    # non-interactive even when upgrading over a modified /etc/nginx/nginx.conf.
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb_path"
}

download_geosite() {
    mkdir -p "$(dirname "$GEOSITE_PATH")"
    if [[ -f "$GEOSITE_PATH" ]]; then
        log "dlc.dat already present at $GEOSITE_PATH — keeping existing"
        return
    fi
    log "Downloading geosite dlc.dat"
    local tmp
    tmp="$(mktemp)"
    if wget -q -O "$tmp" "$GEOSITE_URL"; then
        mv "$tmp" "$GEOSITE_PATH"
        chmod 644 "$GEOSITE_PATH"
        log "Installed $GEOSITE_PATH ($(stat -c%s "$GEOSITE_PATH") bytes)"
    else
        rm -f "$tmp"
        warn "Failed to download dlc.dat — nginx will fail to start until you install it manually:"
        warn "  wget -O $GEOSITE_PATH $GEOSITE_URL"
    fi
}

ensure_cron() {
    # The .deb installs /etc/cron.weekly/refresh-geosite; verify it's there + executable
    if [[ -x /etc/cron.weekly/refresh-geosite ]]; then
        log "Weekly dlc.dat auto-refresh enabled via /etc/cron.weekly/refresh-geosite"
    else
        warn "/etc/cron.weekly/refresh-geosite missing or not executable"
    fi
}

enable_service() {
    log "Enabling nginx.service (will start on boot)"
    systemctl enable nginx.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
}

start_service() {
    log "Starting nginx.service"
    if systemctl start nginx.service; then
        systemctl status nginx.service --no-pager -l || true
    else
        warn "nginx failed to start. Check:"
        warn "  systemctl status nginx.service -l"
        warn "  journalctl -u nginx --no-pager -n 30"
        warn "  nginx -t"
    fi
}

print_next_steps() {
    cat <<'EOF'

┌──────────────────────────────────────────────────────────────────────┐
│                    nginx-geosite installed                          │
├──────────────────────────────────────────────────────────────────────┤
│  Binary:  /usr/sbin/nginx                                           │
│  Config:  /etc/nginx/nginx.conf                                     │
│  Example: /etc/nginx/nginx.conf.example                             │
│  Docs:    /usr/share/doc/nginx-geosite/GEOSITE.md                   │
│  Geo DB:  /usr/local/etc/xray/domains/dlc.dat                       │
│  Cron:    /etc/cron.weekly/refresh-geosite (auto-updates dlc.dat)   │
├──────────────────────────────────────────────────────────────────────┤
│ Next steps:                                                         │
│   1. Edit /etc/nginx/nginx.conf                                     │
│      (or: cp /etc/nginx/nginx.conf.example /etc/nginx/nginx.conf)   │
│   2. nginx -t                                                       │
│   3. systemctl start nginx                                          │
│   4. tail -f /var/log/nginx/nginx-access.log                        │
└──────────────────────────────────────────────────────────────────────┘

EOF
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

uninstall() {
    require_root
    log "Stopping nginx"
    systemctl stop nginx.service 2>/dev/null || true
    log "Removing nginx-geosite package"
    apt-get remove -y nginx-geosite 2>/dev/null || apt-get remove -y nginx 2>/dev/null || true
    log "Removed."
    log "Note: /etc/nginx/ and /usr/local/etc/xray/domains/ preserved"
    log "To purge completely: apt-get purge nginx-geosite"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local do_start=0
    local do_uninstall=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --start)      do_start=1 ;;
            --uninstall)  do_uninstall=1 ;;
            --help|-h)
                grep -E '^# (Usage|What it does|Flags)' "$0" -A 10 | sed 's/^# //; s/^#//'
                exit 0
                ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
        shift
    done

    if [[ $do_uninstall -eq 1 ]]; then
        uninstall
        exit 0
    fi

    require_root
    log "Installing nginx-geosite"

    # Force --force-confold globally for the duration of this install.
    # This is the bulletproof way to prevent dpkg conffile prompts —
    # any dpkg invocation (apt-get install, dpkg --configure, postinst)
    # will keep the existing conffile instead of prompting.
    force_confold_setup
    trap "force_confold_cleanup" EXIT

    # Repair any half-configured dpkg state from a previous broken install
    # (e.g. a prior run that aborted on a conffile prompt). Safe no-op if clean.
    repair_dpkg_state

    local distro
    distro="$(detect_distro)"
    if [[ "$distro" != "debian" ]]; then
        die "This installer only supports Debian/Ubuntu. Detected: $distro"
    fi

    local arch
    arch="$(detect_arch)"
    log "Detected arch: $arch"

    install_deps

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'; force_confold_cleanup" EXIT

    local deb_path
    deb_path="$(download_latest_deb "$arch" "$tmp_dir")"
    install_deb "$deb_path"

    download_geosite
    ensure_cron
    enable_service

    if [[ $do_start -eq 1 ]]; then
        start_service
    fi

    print_next_steps

    if [[ $do_start -eq 0 ]]; then
        log "Service NOT started automatically — edit /etc/nginx/nginx.conf first,"
        log "then run: systemctl start nginx"
        log "(Re-run with --start to skip this gate.)"
    fi
}

main "$@"
