# nginx-geosite packaging

This directory contains everything needed to build, publish, and install
the nginx-geosite Debian package (`.deb`) for amd64 and arm64.

## Files

| File | Purpose |
|------|---------|
| `install.sh` | End-user one-line installer (curl \| bash). Detects arch, downloads the right `.deb` from GitHub Releases, installs it, fetches `dlc.dat`, sets up auto-refresh cron. |
| `build-deb.sh` | Build script — runs `./configure && make && dpkg-deb --build` for the current arch. Used both locally and by CI. |
| `nginx.service` | systemd unit shipped inside the `.deb`. Includes `AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE`. |
| `nginx.conf.example` | Example config that ships inside the `.deb` as `/etc/nginx/nginx.conf.example`. Mirrors the Xray routing rules. |
| `refresh-geosite` | Cron script (weekly) that refreshes `dlc.dat` and reloads nginx. Installed to `/etc/cron.weekly/refresh-geosite`. |
| `../.github/workflows/release.yml` | CI workflow that builds both arches on tag push and creates a GitHub Release. |

The maintainer scripts (`postinst`, `prerm`, `postrm`, `preinst`) are
generated inline by `build-deb.sh` rather than kept as separate files,
because they need version/arch info.

## End-user install (one line)

```bash
curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash
```

This will:
1. Detect architecture (amd64 or arm64)
2. Fetch the latest release `.deb` from GitHub
3. `apt install` it (replaces stock `nginx` if present)
4. Download `dlc.dat` to `/usr/local/etc/xray/domains/dlc.dat`
5. Set up weekly cron auto-refresh of `dlc.dat`
6. Enable `nginx.service` (does NOT start — config may need editing first)

To install AND start immediately:

```bash
curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash -s -- --start
```

## What the package installs

| Path | What |
|------|------|
| `/usr/sbin/nginx` | The binary (with `cap_net_raw,cap_net_bind_service+ep`) |
| `/etc/nginx/nginx.conf` | Default config (conffile — preserved on upgrade) |
| `/etc/nginx/nginx.conf.example` | Example config with geosite + proxy_interface |
| `/etc/nginx/mime.types`, `fastcgi_params`, `fastcgi.conf`, `uwsgi_params`, `scgi_params` | Standard nginx config files |
| `/etc/systemd/system/nginx.service` | systemd unit |
| `/etc/cron.weekly/refresh-geosite` | Auto-refresh script for `dlc.dat` |
| `/var/log/nginx/` | Log directory (created by `postinst`) |
| `/var/lib/nginx/` | State directory (temp files etc.) |
| `/usr/share/doc/nginx-geosite/` | Documentation |

## What the package conflicts with

- `nginx`, `nginx-common`, `nginx-full`, `nginx-light`, `nginx-extras`

The Debian stock nginx packages. `apt install nginx-geosite` cleanly
replaces them (via `Conflicts` + `Replaces` + `Provides: nginx`).

## Cut a new release

```bash
# 1. Make sure master is clean and pushed
git checkout master
git pull

# 2. Tag with the version you want
git tag v1.31.8+cddeppe1
git push origin v1.31.8+cddeppe1

# 3. Watch CI build both arches:
#    https://github.com/cddeppe/nginx/actions
#
# 4. When CI is green, the Release is published automatically:
#    https://github.com/cddeppe/nginx/releases
#
# 5. Test the install script:
#    curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash
```

## Build locally (without CI)

To build a `.deb` on your own machine (must match the target arch):

```bash
# On an amd64 box:
git clone https://github.com/cddeppe/nginx.git
cd nginx
chmod +x packaging/build-deb.sh
sudo ./packaging/build-deb.sh

# Output: packaging/out/nginx-geosite_<version>_amd64.deb
```

To build for arm64 on an amd64 box, you'd need qemu + cross-compiler —
easier to use the CI workflow or run `build-deb.sh` on an actual arm64
machine (RPi 4, Apple Silicon, AWS Graviton, etc.).

## Uninstall

```bash
# Via the install script:
curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash -s -- --uninstall

# Or directly:
sudo apt-get remove nginx-geosite
sudo apt-get purge nginx-geosite   # also removes /var/log/nginx, etc.
```

## Inspect a built .deb

```bash
dpkg-deb --info nginx-geosite_*.deb       # metadata
dpkg-deb -c nginx-geosite_*.deb           # contents
dpkg-deb -e nginx-geosite_*.deb /tmp/scripts  # extract maintainer scripts
```

## How the install flow works end-to-end

```
User runs: curl ... | sudo bash
            │
            ▼
       install.sh
            │
            ├── detect arch (uname -m → amd64/arm64)
            ├── curl GitHub API → latest release → find .deb URL for arch
            ├── wget .deb to /tmp
            ├── apt-get install -y /tmp/nginx-geosite-*.deb
            │        │
            │        ├── preinst: stop running nginx
            │        ├── unpack .deb → filesystem
            │        └── postinst:
            │             ├── create nginx/www-data users
            │             ├── mkdir /var/log/nginx, /var/lib/nginx, /run/lock
            │             ├── setcap cap_net_raw,cap_net_bind_service+ep /usr/sbin/nginx
            │             ├── download dlc.dat to /usr/local/etc/xray/domains/
            │             └── systemctl enable nginx.service
            │
            ├── (cron.weekly/refresh-geosite already installed by .deb)
            ├── systemctl daemon-reload
            └── print next steps (edit /etc/nginx/nginx.conf, then start)
```

## Test the install on a fresh VM

The safest way to validate the package end-to-end is on a clean Debian
or Ubuntu VM (e.g. via `cloud-localds` or a LXC container):

```bash
# On your dev machine:
multipass launch --name nginx-test 22.04
multipass shell nginx-test

# Inside the VM:
curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash -s -- --start
sudo cp /etc/nginx/nginx.conf.example /etc/nginx/nginx.conf
sudo nginx -t && sudo systemctl restart nginx
```
