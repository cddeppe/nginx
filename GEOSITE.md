# nginx fork: geosite routing + per-interface bind

This fork adds two features to nginx stream module that, together, replicate
Xray's `geosite:` + `sockopt.interface` routing in nginx:

1. **`ngx_stream_geosite_module`** — loads a v2ray/xray `geosite.dat` file
   (a.k.a. `dlc.dat`), parses the protobuf, builds in-memory hash tables,
   and exposes the variable `$geosite_category`. For a given TLS connection,
   `$geosite_category` returns the tag of the matching geosite category
   (e.g. `"amazon"`, `"netflix"`), or the empty string if no category matches.

2. **`proxy_interface` directive** (added to `ngx_stream_proxy_module`)
   — binds the upstream connection to a named network interface via
   `SO_BINDTODEVICE`. This is the true Linux equivalent of Xray's
   `sockopt.interface`: it pins the connection to an interface **by name**,
   regardless of IP address. Combined with a `map` on `$geosite_category`,
   this gives you Xray-equivalent per-domain routing through WireGuard (or
   any other interface) — without maintaining Xray alongside nginx.

## Build

```bash
./auto/configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --prefix=/usr/local/nginx
make -j$(nproc)
sudo make install
```

The geosite module is built automatically whenever `--with-stream` is given.
No external libraries are required — the protobuf parser is hand-rolled for
the tiny geosite schema.

## Runtime: CAP_NET_RAW is mandatory

`SO_BINDTODEVICE` requires `CAP_NET_RAW`. Three options, easiest first:

```bash
# (1) Set capability on the binary (preferred)
sudo setcap cap_net_raw+ep /usr/local/nginx/sbin/nginx
```

```ini
# (2) systemd unit
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
```

```nginx
# (3) Run workers as root (not recommended)
user root;
```

If you skip this, every connection through `proxy_interface` will fail with:

```
setsockopt(SO_BINDTODEVICE, "wg0") failed (1: Operation not permitted)
```

## Configuration

### Stream block — load geosite, set up routing

```nginx
stream {
    log_format basic '$remote_addr [$time_local] '
                     '--$ssl_alpn_protocol $ssl_preread_server_name $server_port '
                     '--serveraddr:$server_addr --$ssl_server_name $hostname '
                     '[$geosite_category]';
    access_log /var/log/nginx/nginx-access.log basic buffer=256k flush=5s;

    # 1. Load the geosite database (download from
    #    https://github.com/v2fly/domain-list-community/releases, the
    #    file is `dlc.dat` aka `geosite.dat`).
    geosite_load /usr/local/etc/xray/domains/dlc.dat;

    # 2. Optional: only load specific categories to save memory
    #    (~50 MB per category with all entries). If omitted, all
    #    categories in the file are loaded.
    geosite_filter amazon hulu disney netflix google;

    # 2b. Optional: tune hash table sizing. Defaults are usually fine,
    #     but if you see "could not build geosite_domain_hash, you should
    #     increase geosite_hash_bucket_size" in error.log, bump bucket_size
    #     (typically double it). Some real geosite categories have entries
    #     > 80 bytes (long cloudfront / aws subdomains), which is why the
    #     default is 256 rather than the nginx standard 64.
    # geosite_hash_bucket_size 256;
    # geosite_hash_max_size 16384;

    # 3. Map SNI → backend (existing logic)
    map $ssl_preread_server_name $target_backend {
        nas.deppe.cc  "$ssl_preread_server_name:3064";
        default       "$ssl_preread_server_name:$server_port";
    }

    # 4. Map geosite category → egress interface name.
    #    This is the routing decision: which WireGuard tunnel (if any)
    #    should this connection go through?
    map $geosite_category $egress_iface {
        default  off;          # no bind → use main routing table
        amazon   ak;           # wg-quick interface 'ak'
        hulu     ak;
        disney   ak;
        netflix  ak;

        # also support explicit per-domain rules (Xray "domain:" entries)
        # via additional map blocks if you need them:
        # $ssl_preread_server_name → $egress_iface override
    }

    # Optional: also route specific bare domains without geosite
    map $ssl_preread_server_name $egress_override {
        default                          "";
        ~*\.intuit\.com$                ak;
        ~*\.intuitcdn\.net$             ak;
    }

    map $egress_override $final_iface {
        ""      $egress_iface;
        default $egress_override;
    }

    server {
        listen 82.21.4.42:443 bind reuseport so_keepalive=on rcvbuf=1024m sndbuf=512m fastopen=256;
        listen [2a0e:7d43:0:1::1]:443 bind reuseport so_keepalive=on rcvbuf=1024m sndbuf=512m fastopen=256;

        resolver 127.0.0.1 [::1] ipv4=on ipv6=on valid=30s;
        preread_buffer_size 16k;
        preread_timeout 30s;
        ssl_preread on;
        tcp_nodelay on;

        proxy_timeout 4h;
        proxy_connect_timeout 30s;
        proxy_buffer_size 2048k;
        proxy_socket_keepalive on;
        proxy_ssl_session_reuse off;

        # 5. The hook: bind upstream socket to the chosen interface.
        #    Empty string or "off" → no bind (uses default route).
        proxy_interface $final_iface;

        proxy_pass $target_backend;
    }

    # Backend NAS blocks (unchanged from upstream nginx usage)
    server {
        listen 3064 bind reuseport so_keepalive=off rcvbuf=1024m sndbuf=512m fastopen=256;
        listen [::]:3064 bind reuseport so_keepalive=off rcvbuf=1024m sndbuf=512m fastopen=256;
        resolver 127.0.0.1 [::1] ipv4=on ipv6=off valid=1s;
        proxy_pass nas.deppe.cc:3064;
    }
}
```

### Verifying it works

```bash
# 1. Confirm geosite loaded at startup
sudo tail -100 /var/log/nginx/error.log | grep geosite_load
# Expected: "geosite_load: loaded /usr/local/etc/xray/domains/dlc.dat (NNN bytes), parsing..."
#           "geosite_load: parsed N categories, NNNN total domains"

# 2. Confirm a connection actually goes through WireGuard
sudo tcpdump -ni ak -c 5
# In another terminal:
curl -k --resolve www.amazon.com:443:82.21.4.42 https://www.amazon.com/
# tcpdump should show SYN packets to amazon's IPs leaving the 'ak' interface.

# 3. Confirm non-matching SNIs do NOT go through WG
curl -k --resolve example.com:443:82.21.4.42 https://example.com/
# tcpdump on 'ak' should show nothing.

# 4. Inspect the socket
sudo ss -tnpie | grep nginx
# Look for: ifc:ak on the upstream socket line.
```

## Mapping Xray config to nginx config

| Xray config                          | nginx equivalent                                    |
|--------------------------------------|-----------------------------------------------------|
| `geosite.path`                       | `geosite_load /path/to/dlc.dat;`                    |
| `geosite:amazon` (in routing rules)  | `$geosite_category == "amazon"` (auto, via variable)|
| `outboundTag: wireguard-usa`         | `map $geosite_category $egress_iface { amazon ak; }`|
| `sockopt.interface: "ak"`            | `proxy_interface $egress_iface;`                    |
| `sockopt.tcpFastOpen: true`          | `fastopen=256` on `listen` (client TFO is sysctl)   |
| `sockopt.tcpNoDelay: true`           | `tcp_nodelay on;`                                   |
| `sockopt.tcpKeepAlive: 15`           | `so_keepalive=15s:15s:8;`                            |
| `sockopt.tcpMptcp: true`             | `sysctl net.mptcp.enabled=1` (transparent to nginx) |
| `domain: ["intuit.com", "*.intuit.com"]` | `map ~*\.intuit\.com$ ak;` (regex map)         |
| `outboundTag: block` (blackhole)     | `proxy_pass 127.0.0.1:9;` (or a custom reject server) |

## How matching works

For each connection, the variable `$geosite_category` is evaluated:

1. Read `$ssl_preread_server_name` (requires `ssl_preread on;`).
2. Lowercase it.
3. For each loaded geosite category, in the order they appear in the file:
   - **Full match** — exact equality with a `Domain.Type=Full` entry.
   - **Suffix match** — try each suffix of the SNI (e.g. for
     `www.amazon.com`, try `www.amazon.com`, `amazon.com`, `com`) against
     the `Domain.Type=Domain` entries. Any hit → match. This correctly
     rejects `notamazon.com` because `amazon.com` is not a suffix of
     `notamazon.com`.
   - **Plain match** — substring search against `Domain.Type=Plain`
     entries. Linear scan; rare in geosite files.
4. First matching category wins. Variable returns its tag (e.g. `"amazon"`).
5. If no category matches, variable is empty.

Regex entries (`Domain.Type=Regex`) are counted but not matched. A
warning is logged at load time if any are encountered.

## Memory and performance

- dlc.dat is ~10 MB on disk; the in-memory hash tables add ~5x that per
  category loaded (~50 MB per category with all entries). Loading all
  ~250 categories in `geosite.dat` uses ~1 GB; use `geosite_filter` to
  limit if memory matters.
- All structures are allocated in `cf->cycle->pool` at config-parse time.
  Workers inherit them via `fork()` copy-on-write. No per-worker loading.
- Lookup cost: ~O(labels in SNI) hash lookups + a single substring scan
  if plain entries exist. For typical SNIs this is a few microseconds.
- Reload (`nginx -s reload`) re-parses the file from scratch. There is
  no incremental update.

## Limitations / TODO

- **No IPv6-only matching caveat**: nginx hashes are case-insensitive
  ASCII. IDN/Punycode domains work as-is since they're already ASCII in
  the geosite file. Non-ASCII SNIs are not lowercased by `ngx_strlow`
  in the way you'd want; this is rarely an issue in practice.
- **No regex matching**: regex entries are skipped. If a category you
  care about relies on regex rules, those won't match. The matcher
  counts and logs the number skipped per category.
- **No `geosite:category!cn`-style attribute filtering**: v2ray supports
  entries with `@cn` attributes in the source list. The compiled
  `dlc.dat` includes these as separate categories (e.g. `google`, but
  also `google@cn`), so you can match them by listing both in
  `geosite_filter`.
- **`SO_BINDTODEVICE` is Linux-only**. The fork guards the new code with
  `#if (NGX_LINUX)`. On other platforms, `proxy_interface` parses
  successfully but does nothing (a warning is logged at connect time).
- **No incremental reload of geosite data**. To update the file, replace
  it on disk and run `nginx -s reload`. The new file is fully re-parsed.

## File layout of the changes

```
src/event/ngx_event_connect.h          + ngx_str_t *interface field
src/event/ngx_event_connect.c          + SO_BINDTODEVICE call (Linux)
src/stream/ngx_stream_proxy_module.c   + proxy_interface directive
                                         + ngx_stream_proxy_set_interface()
src/stream/ngx_stream_geosite_module.c NEW — geosite loader + matcher
auto/modules                           + register geosite module
```

## License

nginx is BSD-2-Clause. This fork's additions are MIT. See `LICENSE`.
