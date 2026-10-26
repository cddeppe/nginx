# nginx fork: route_group transport failover

This fork directive set adds **health-aware transport failover** to the
stream module. When you route traffic through a chain of transports
(direct path, WireGuard tunnel, Cloudflare Tunnel, ...), `route_group`
continuously measures each path and steers **new connections** to the
best healthy member — automatically, with hysteresis, and without
ever blackholing.

It exists because maps can only pick a *static* egress port. If the
chosen transport degrades (congestion, packet loss, tunnel flap), the
map keeps sending traffic into the degraded path until a human notices.
`route_group` closes that gap.

## Quick example

```nginx
stream {
    # how each path is measured ------------------------------------------
    path_probe direct_probe {
        target 198.51.100.10:443;      # far-end box, bare TCP connect
        mode tcp;
        interval 1s;
        timeout 3s;
    }
    path_probe tunnel_probe {
        target 127.0.0.1:12443;        # local tunnel listener
        sni www.cloudflare.com;        # real SNI, bytes must traverse
        mode tls;
        interval 1s;
        timeout 3s;
    }

    # failover group -------------------------------------------------------
    route_group al_transport {
        server 127.0.0.1:11443 priority=1 probe=direct_probe;  # direct
        server 127.0.0.1:12443 priority=2 probe=tunnel_probe;  # tunnel

        degrade_rtt_ratio  1.8;
        degrade_fail_pct   20;
        down_fail_streak   3;
        sustain            3;
        failback           120s;
    }

    # maps emit group names (failover-aware) or raw addr:port (hard pin)
    map $ssl_preread_server_name $route_target {
        default                 al_transport;
        ~*^dns\.example\.com$   127.0.0.1:11443;   # pinned, no failover
    }

    server {
        listen 0.0.0.0:443;
        ssl_preread on;
        proxy_pass $route_target;      # group name -> healthy member addr
    }
}
```

## Directives

### `path_probe <name> { ... }`

Defines one active measurement. One `path_probe` may be referenced by
any number of group members.

| directive | meaning |
|---|---|
| `target <addr:port>` | probe destination (IP literal, or `[v6]:port`) |
| `sni <name>` | SNI carried in the probe ClientHello (`mode tls` only) |
| `mode tcp\|tls` | `tcp` = bare connect; `tls` = minimal ClientHello, time-to-first-byte |
| `interval <t>` | probe period (default `1s`) |
| `timeout <t>` | per-probe deadline (default `3s`) |

**Why two modes.** A bare TCP connect measures pure path RTT/loss and
depends on nothing at the far end — ideal for a direct path whose
remote endpoint is your own box. But a *local tunnel listener*
(cloudflared, WireGuard-backed socks, ...) accepts the TCP handshake
even when the tunnel behind it is dead. For those, `mode tls` pushes a
minimal ClientHello carrying a **real SNI**: the bytes must survive the
whole tunnel, be preread, resolved and answered at the far end. Use a
SNI that certainly exists but is not business-critical (e.g.
`www.cloudflare.com`). A made-up SNI is a dead end on SNI-passthrough
egresses (far-end resolves the probe name literally).

### `route_group <name> { ... }`

| directive | meaning | default |
|---|---|---|
| `server <addr:port> priority=N probe=<name>` | member; lower priority wins | required |
| `degrade_rtt_ratio <r>` | EWMA/baseline ratio that counts as degraded | `1.8` |
| `degrade_fail_pct <p>` | failed-probe % over the last 32 probes | `20` |
| `down_fail_streak <n>` | consecutive probe failures → DOWN | `3` |
| `sustain <n>` | consecutive bad evals before leaving UP | `3` |
| `failback <t>` | continuous health required to return to UP | `120s` |

## State machine

Each member is `UP`, `DEGRADED` or `DOWN`.

- **UP → DEGRADED**: RTT EWMA exceeds `degrade_rtt_ratio` × its own
  baseline (learned from its healthy history; EWMA rises fast at 1/8,
  decays slow at 1/3), or the rolling failure percentage exceeds
  `degrade_fail_pct`. Needs `sustain` consecutive bad evaluations.
- **anything → DOWN**: `down_fail_streak` consecutive probe timeouts.
  DOWN always fires, even under shared-fate suppression (below).
- **DEGRADED/DOWN → UP**: only after `failback` of continuously healthy
  probes. Recovery from a failure streak resets the failure window on
  the *first* success, so dilution lag does not delay healing.

**Selection** (never blackholes): first member that is UP by priority;
if none, first DEGRADED; if none, member 0. Traffic always has an
address to go to.

**Shared fate**: if *every* member is bad at once, the likely cause is
the local uplink, not three transports failing independently. Metric
DEGRADATION is then suppressed (flapping is pointless), but DOWN for
real hard failures is still allowed. The condition and its clearing are
logged.

## `proxy_pass` integration

When an evaluated `proxy_pass` target (variable form) resolves to a
**route_group name**, the runtime substitutes the currently-selected
healthy member address. A raw `addr:port` target passes through
untouched — this is the escape hatch for hosts you want **hard-pinned**
to one transport with no failover (e.g. DNS endpoints whose resolver
behavior you do not want to change mid-session).

In-flight connections are never migrated; only new connections follow
selection changes. Existing TCP sessions self-heal or time out on their
own — that keeps semantics simple and avoids mid-stream address swaps.

## Log variables

| variable | value |
|---|---|
| `$route_member` | selected member index |
| `$route_member_addr` | selected member address (`127.0.0.1:11443`) |
| `$route_member_state` | member state at selection time (`up`/`degraded`/`down`) |
| `$route_member_rtt` | member RTT EWMA, milliseconds |

State transitions are logged at `notice` level, prefixed
`route_group`, including the numbers that caused them:

```
route_group "al_transport": member 0 (127.0.0.1:11443) state up -> degraded
    (ewma=61.5ms baseline=29.8ms fail_streak=0)
```

Watch them with:

```bash
tail -f /var/log/nginx/error.log | grep route_group
```

## Reloads

Group state lives in a per-group shared-memory zone: a config reload
keeps member states, EWMA and baselines. Probe duty is held by one
elected worker (pid + 1 s heartbeat); on reload or crash the leader
role is taken over within a second, and draining old workers do not
keep it.

## Build

Compiled automatically whenever `--with-stream` is configured — no
extra flag, no external dependency.

## Not in this version (deliberately)

- **Passive retransmit measurement** of real traffic (TCP_INFO
  sampling) — active probes only for now.
- **Mid-flow eviction / migration** of established connections.
- **Weighted traffic splitting** between healthy members.

Tuning advice: before changing thresholds, read a few real transitions
from the error log (they print ewma/baseline/fail_streak) and set
`degrade_rtt_ratio` / `degrade_fail_pct` / `sustain` from the numbers
you actually see.
