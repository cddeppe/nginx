#!/bin/bash
#
# build-deb.sh — build a .deb package for nginx-geosite on the current arch.
#
# Usage:
#   ./packaging/build-deb.sh            # build for current arch
#   ./packaging/build-deb.sh /tmp/out   # build, place .deb in /tmp/out
#
# Output:
#   nginx-geosite_<version>_<arch>.deb
#
# Requirements (Debian/Ubuntu):
#   apt install -y build-essential libpcre2-dev libssl-dev zlib1g-dev \
#                   libcap2-bin dpkg-dev git
#
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/packaging/out}"
mkdir -p "$OUT_DIR"

# Detect arch via dpkg
ARCH="$(dpkg --print-architecture)"
if [[ -z "$ARCH" ]]; then
    echo "ERROR: could not detect architecture via dpkg" >&2
    exit 1
fi

# Version: derive from git tag if available, else from src/core/nginx.h + git sha
VERSION="$(awk '/^#define NGINX_VERSION/ {gsub(/"/, "", $3); print $3}' \
           "$REPO_ROOT/src/core/nginx.h")"
GIT_DESCRIBE="$(cd "$REPO_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo "local")"

# Compute the Debian package version.
# Strategy: prefer the git tag (when we're on a release tag like v1.31.8+cddeppe1),
# otherwise fall back to <nginx_version>+<git_describe>.
#
# Examples:
#   git describe = "v1.31.8+cddeppe1"   -> PKG_VERSION = "1.31.8+cddeppe1"
#   git describe = "v1.31.8+cddeppe1-3-gabcd"  -> "1.31.8+cddeppe1.3.gabcd"
#   git describe = "local" (no tags)     -> PKG_VERSION = "<nginx_version>+cddeppe1"
if [[ "$GIT_DESCRIBE" != "local" ]]; then
    # Strip leading "v"
    PKG_VERSION="${GIT_DESCRIBE#v}"
    # Convert "1.31.8+cddeppe1-3-gabcd123-dirty" to "1.31.8+cddeppe1.3.gabcd123.dirty"
    # Debian version strings can't have "-" (used as separator between version and revision),
    # so we replace with ".". "+" is OK in the upstream version part.
    PKG_VERSION="${PKG_VERSION//-/.}"
else
    PKG_VERSION="${VERSION}+cddeppe1"
fi

# Defensive: if for some reason the version still doesn't include the nginx
# version, prepend it.
if [[ "$PKG_VERSION" != "$VERSION"* ]]; then
    PKG_VERSION="${VERSION}+${PKG_VERSION}"
fi

PKG_NAME="nginx-geosite"
DEB_NAME="${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"
WORK_DIR="$(mktemp -d)"
trap "rm -rf '$WORK_DIR'" EXIT

echo "==> Building $PKG_NAME $PKG_VERSION for $ARCH"
echo "    Source:  $REPO_ROOT"
echo "    Output:  $OUT_DIR/$DEB_NAME"
echo "    Workdir: $WORK_DIR"

# ---------------------------------------------------------------------------
# 2. Install build deps if missing
# ---------------------------------------------------------------------------

NEEDED=(build-essential libpcre2-dev libssl-dev zlib1g-dev libcap2-bin dpkg-dev git)
MISSING=()
for pkg in "${NEEDED[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING+=("$pkg")
    fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "==> Installing missing build deps: ${MISSING[*]}"
    apt-get update -qq
    apt-get install -y --no-install-recommends "${MISSING[@]}"
fi

# ---------------------------------------------------------------------------
# 3. Build nginx
# ---------------------------------------------------------------------------

BUILD_DIR="$WORK_DIR/build"
mkdir -p "$BUILD_DIR"
cd "$REPO_ROOT"

echo "==> Configuring nginx"
./auto/configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --prefix=/usr/share/nginx \
    --sbin-path=/usr/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/run/nginx.pid \
    --lock-path=/run/lock/nginx.lock \
    --modules-path=/usr/lib/nginx/modules \
    --http-client-body-temp-path=/var/lib/nginx/body \
    --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
    --http-proxy-temp-path=/var/lib/nginx/proxy \
    --http-scgi-temp-path=/var/lib/nginx/scgi \
    --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
    >"$BUILD_DIR/configure.log" 2>&1

echo "==> Compiling"
make -j"$(nproc)" >"$BUILD_DIR/build.log" 2>&1

# ---------------------------------------------------------------------------
# 4. Assemble the .deb filesystem
# ---------------------------------------------------------------------------

PKG_ROOT="$WORK_DIR/$PKG_NAME"
mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/usr/sbin"
mkdir -p "$PKG_ROOT/usr/share/doc/$PKG_NAME"
mkdir -p "$PKG_ROOT/usr/share/nginx"
mkdir -p "$PKG_ROOT/etc/nginx"
mkdir -p "$PKG_ROOT/etc/systemd/system"
mkdir -p "$PKG_ROOT/etc/cron.weekly"
mkdir -p "$PKG_ROOT/etc/nginx/conf.d"
mkdir -p "$PKG_ROOT/var/lib/nginx"
mkdir -p "$PKG_ROOT/var/log/nginx"

# Binary
cp "$REPO_ROOT/objs/nginx" "$PKG_ROOT/usr/sbin/nginx"
chmod 755 "$PKG_ROOT/usr/sbin/nginx"

# Default config (only install if not already present on target system —
# we use 'package provides but doesn't overwrite' via dpkg-conffile pattern)
mkdir -p "$PKG_ROOT/etc/nginx"
cp "$REPO_ROOT/conf/mime.types" "$PKG_ROOT/etc/nginx/mime.types"
cp "$REPO_ROOT/conf/fastcgi_params" "$PKG_ROOT/etc/nginx/fastcgi_params"
cp "$REPO_ROOT/conf/fastcgi.conf" "$PKG_ROOT/etc/nginx/fastcgi.conf"
cp "$REPO_ROOT/conf/uwsgi_params" "$PKG_ROOT/etc/nginx/uwsgi_params"
cp "$REPO_ROOT/conf/scgi_params" "$PKG_ROOT/etc/nginx/scgi_params"

# Example config (the geosite-routing one) — install as .example, don't overwrite
if [[ -f "$REPO_ROOT/packaging/nginx.conf.example" ]]; then
    cp "$REPO_ROOT/packaging/nginx.conf.example" \
       "$PKG_ROOT/etc/nginx/nginx.conf.example"
fi
# QUIC relay example config (standalone drop-in for a relay VPS)
if [[ -f "$REPO_ROOT/packaging/quic-relay.conf.example" ]]; then
    cp "$REPO_ROOT/packaging/quic-relay.conf.example" \
       "$PKG_ROOT/etc/nginx/quic-relay.conf.example"
fi
# Main nginx.conf — only install if user doesn't have one. Use dpkg-conffile
# to make it a conffile (preserved on upgrade).
if [[ ! -f "$PKG_ROOT/etc/nginx/nginx.conf" ]] && [[ -f "$REPO_ROOT/packaging/nginx.conf.example" ]]; then
    cp "$REPO_ROOT/packaging/nginx.conf.example" "$PKG_ROOT/etc/nginx/nginx.conf"
fi

# systemd unit — install to both /etc/systemd/system (active location) and
# /usr/share/doc/nginx-geosite/ (canonical source for install.sh to copy
# from on upgrade, in case dpkg didn't replace the active one)
cp "$REPO_ROOT/packaging/nginx.service" "$PKG_ROOT/etc/systemd/system/nginx.service"
chmod 644 "$PKG_ROOT/etc/systemd/system/nginx.service"
cp "$REPO_ROOT/packaging/nginx.service" "$PKG_ROOT/usr/share/doc/nginx-geosite/nginx.service"
chmod 644 "$PKG_ROOT/usr/share/doc/nginx-geosite/nginx.service"

# cron weekly refresh of dlc.dat
cp "$REPO_ROOT/packaging/refresh-geosite" "$PKG_ROOT/etc/cron.weekly/refresh-geosite"
chmod 755 "$PKG_ROOT/etc/cron.weekly/refresh-geosite"

# Docs
cp "$REPO_ROOT/GEOSITE.md" "$PKG_ROOT/usr/share/doc/$PKG_NAME/GEOSITE.md"
[[ -f "$REPO_ROOT/QUIC-RELAY.md" ]] && \
    cp "$REPO_ROOT/QUIC-RELAY.md" "$PKG_ROOT/usr/share/doc/$PKG_NAME/QUIC-RELAY.md"
cp "$REPO_ROOT/LICENSE" "$PKG_ROOT/usr/share/doc/$PKG_NAME/copyright" 2>/dev/null || true
cat > "$PKG_ROOT/usr/share/doc/$PKG_NAME/README" <<EOF
$PKG_NAME $PKG_VERSION ($ARCH)

nginx fork with:
  - ngx_stream_geosite_module: load v2ray/xray geosite.dat, expose
    \$geosite_category variable
  - proxy_interface directive: bind upstream socket to a named network
    interface via SO_BINDTODEVICE (Linux)
  - ngx_stream_quic_relay_module: QUIC-aware UDP relay for DNS-hijack
    topologies — survives Android/Cronet connection migration
    (see /usr/share/doc/nginx-geosite/QUIC-RELAY.md)

QUIC relay quickstart:
  1. sudo cp /etc/nginx/quic-relay.conf.example /etc/nginx/nginx.conf
  2. sudo nginx -t && sudo systemctl restart nginx
  3. point DNS for google.com/youtube.com at this box
  Docs: /usr/share/doc/nginx-geosite/QUIC-RELAY.md

Source: https://github.com/cddeppe/nginx
Documentation: /usr/share/doc/$PKG_NAME/GEOSITE.md
                also: man nginx

Quick start:
  1. Edit /etc/nginx/nginx.conf (or copy nginx.conf.example over it)
  2. systemctl start nginx
  3. tail -f /var/log/nginx/nginx-access.log to see routing decisions
EOF

# ---------------------------------------------------------------------------
# 5. Debian control + maintainer scripts
# ---------------------------------------------------------------------------

# Compute installed size (KB)
INSTALLED_SIZE="$(du -sk "$PKG_ROOT" | awk '{print $1}')"

# Dependencies: shared libs we link against + tools used by maintainer scripts
DEPENDS="libc6, libpcre2-8-0, libssl3t64 | libssl3, zlib1g, adduser, lsb-base, libcap2-bin"

cat > "$PKG_ROOT/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $ARCH
Maintainer: cddeppe <cddeppe@users.noreply.github.com>
Installed-Size: $INSTALLED_SIZE
Depends: $DEPENDS
Conflicts: nginx, nginx-common, nginx-full, nginx-light, nginx-extras
Replaces: nginx, nginx-common, nginx-full, nginx-light, nginx-extras
Provides: nginx, nginx-http-server, nginx-geosite
Section: httpd
Priority: optional
Homepage: https://github.com/cddeppe/nginx
Description: nginx fork with geosite routing, per-interface bind (SO_BINDTODEVICE) and a QUIC relay
 Replaces Xray's geosite: + sockopt.interface routing with native nginx,
 and adds a QUIC-aware UDP relay for DNS-hijack topologies.
 .
 Adds three features to the nginx stream module:
  * ngx_stream_geosite_module: loads v2ray/xray geosite.dat (protobuf),
    exposes the \$geosite_category variable (e.g. "amazon", "netflix") for
    the current \$ssl_preread_server_name.
  * proxy_interface directive: binds the upstream connection to a named
    network interface (e.g. "wg0") via SO_BINDTODEVICE. Requires CAP_NET_RAW.
  * ngx_stream_quic_relay_module: plaintext-UDP QUIC relay with per-session
    connected upstream sockets, Initial SNI extraction for routing, and
    Cronet migration survival (never-seen-DCID miss-rebound). Enables
    native HTTP/3 for DNS-hijacked clients (e.g. Android YouTube).
    Docs: /usr/share/doc/nginx-geosite/QUIC-RELAY.md .
 .
 Together with a map on \$geosite_category, this gives Xray-equivalent
 per-domain routing through WireGuard (or any interface) inside nginx.
 .
 Conflicts/Replaces the Debian nginx package — installs cleanly in its place.
EOF

# Conffiles — preserve these across upgrade
cat > "$PKG_ROOT/DEBIAN/conffiles" <<EOF
/etc/nginx/nginx.conf
/etc/nginx/mime.types
/etc/nginx/fastcgi_params
/etc/nginx/fastcgi.conf
/etc/nginx/uwsgi_params
/etc/nginx/scgi_params
EOF

# Post-install: set capabilities, create dirs, enable service
cat > "$PKG_ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

# Source debconf library
. /usr/share/debconf/confmodule 2>/dev/null || true

# Create nginx user if missing (matches Debian nginx package convention)
if ! getent passwd nginx >/dev/null 2>&1; then
    adduser --system --group --no-create-home --quiet \
            --home /var/lib/nginx --shell /usr/sbin/nologin nginx 2>/dev/null || true
fi
# Also ensure www-data exists (used by stock config)
if ! getent passwd www-data >/dev/null 2>&1; then
    adduser --system --group --no-create-home --quiet \
            --home /var/www --shell /usr/sbin/nologin www-data 2>/dev/null || true
fi

# Create runtime dirs
install -d -o root -g adm -m 2755 /var/log/nginx
install -d -o root -g root -m 755 /var/lib/nginx
install -d -o root -g root -m 755 /var/lib/nginx/body
install -d -o root -g root -m 755 /var/lib/nginx/proxy
install -d -o root -g root -m 755 /var/lib/nginx/fastcgi
install -d -o root -g root -m 755 /var/lib/nginx/scgi
install -d -o root -g root -m 755 /var/lib/nginx/uwsgi
install -d -o root -g root -m 755 /run/lock
install -d -o root -g root -m 755 /usr/local/etc/xray/domains

# Set capabilities on the binary: CAP_NET_RAW (for SO_BINDTODEVICE in
# proxy_interface) + CAP_NET_BIND_SERVICE (for ports < 1024). Belt-and-
# suspenders with the systemd AmbientCapabilities line.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_bind_service+ep /usr/sbin/nginx || \
        echo "WARNING: setcap failed — proxy_interface will not work." >&2
fi

# Download dlc.dat if missing
if [[ ! -f /usr/local/etc/xray/domains/dlc.dat ]]; then
    echo "Downloading geosite dlc.dat..."
    wget -q -O /usr/local/etc/xray/domains/dlc.dat.tmp \
        https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat && \
        mv /usr/local/etc/xray/domains/dlc.dat.tmp /usr/local/etc/xray/domains/dlc.dat && \
        chmod 644 /usr/local/etc/xray/domains/dlc.dat || \
        echo "WARNING: failed to download dlc.dat — install it manually" >&2
fi

# Enable + start systemd unit (only on fresh install, not upgrade)
if [[ "$1" = "configure" ]]; then
    if systemctl is-enabled nginx.service >/dev/null 2>&1; then
        :
    else
        systemctl enable nginx.service 2>/dev/null || true
    fi
    # Don't auto-start — user may need to edit /etc/nginx/nginx.conf first.
    # They can `systemctl start nginx` when ready.
fi

# Reload systemd to pick up the unit file
systemctl daemon-reload 2>/dev/null || true

echo ""
echo "nginx-geosite installed."
echo "  Binary:  /usr/sbin/nginx"
echo "  Config:  /etc/nginx/nginx.conf"
echo "  Docs:    /usr/share/doc/nginx-geosite/GEOSITE.md"
echo "          /usr/share/doc/nginx-geosite/QUIC-RELAY.md"
echo "  Example: /etc/nginx/nginx.conf.example (geosite routing)"
echo "           /etc/nginx/quic-relay.conf.example (QUIC relay VPS)"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/nginx/nginx.conf (or: cp /etc/nginx/nginx.conf.example /etc/nginx/nginx.conf)"
echo "  2. nginx -t           # test config"
echo "  3. systemctl start nginx"
echo "  4. systemctl status nginx"
echo ""

exit 0
POSTINST
chmod 755 "$PKG_ROOT/DEBIAN/postinst"

# Pre-remove: stop service
cat > "$PKG_ROOT/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
if [[ "$1" = "remove" ]] || [[ "$1" = "deconfigure" ]]; then
    systemctl stop nginx.service 2>/dev/null || true
fi
exit 0
PRERM
chmod 755 "$PKG_ROOT/DEBIAN/prerm"

# Post-remove: disable service (on purge, also remove config + state)
cat > "$PKG_ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e
if [[ "$1" = "purge" ]]; then
    systemctl disable nginx.service 2>/dev/null || true
    rm -f /etc/systemd/system/nginx.service
    rm -rf /var/log/nginx /var/lib/nginx
    # Don't remove /etc/nginx — user might have custom configs
    echo "Purged nginx-geosite. /etc/nginx/ preserved (remove manually if desired)."
fi
systemctl daemon-reload 2>/dev/null || true
exit 0
POSTRM
chmod 755 "$PKG_ROOT/DEBIAN/postrm"

# Pre-build: nothing to do, but include for completeness
cat > "$PKG_ROOT/DEBIAN/preinst" <<'PREINST'
#!/bin/bash
set -e
# Stop any running nginx (Debian package or our own) before installing
if systemctl is-active nginx.service >/dev/null 2>&1; then
    systemctl stop nginx.service || true
fi
exit 0
PREINST
chmod 755 "$PKG_ROOT/DEBIAN/preinst"

# ---------------------------------------------------------------------------
# 6. Build the .deb
# ---------------------------------------------------------------------------

echo "==> Building .deb"
# Fix ownership for reproducibility
chown -R root:root "$PKG_ROOT" 2>/dev/null || true
# Build with gzip compression for compatibility
dpkg-deb --root-owner-group --build "$PKG_ROOT" "$OUT_DIR/$DEB_NAME"

echo ""
echo "==> Built: $OUT_DIR/$DEB_NAME"
ls -la "$OUT_DIR/$DEB_NAME"

# Verify (without pipefail killing us on truncated head)
echo ""
echo "==> Package info:"
dpkg-deb --info "$OUT_DIR/$DEB_NAME" 2>&1 | head -20 || true
echo ""
echo "==> Contents (top 20):"
dpkg-deb -c "$OUT_DIR/$DEB_NAME" 2>&1 | head -20 || true

# Cleanup
rm -rf "$WORK_DIR"
trap - EXIT
