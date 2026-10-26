/*
 * ngx_stream_route_group_module
 *
 * Transport failover groups for SNI-routing TLS passthrough setups.
 *
 * A route_group is a named, priority-ordered list of egress "members"
 * (address:port of local egress-hop listeners).  When a `proxy_pass`
 * target evaluates (via variables/maps) to a route_group name, the
 * member actually used is chosen by path health:
 *
 *   1. first (lowest priority number) member in state UP
 *   2. else first member in state DEGRADED
 *   3. else the first member regardless of state (never blackhole)
 *
 * Health is maintained by active probes (one probe runner per group,
 * leader-elected among workers):
 *
 *   path_probe <name> {
 *       target   <ip:port>;   # IP literal required
 *       sni      <name>;      # for mode=tls
 *       mode     tcp|tls;     # tcp = connect-only; tls = ClientHello +
 *                             #      wait for first response byte
 *       interval 1s;
 *       timeout  3s;
 *   }
 *
 *   route_group <name> {
 *       server 127.0.0.1:11443 priority=1 probe=<path_probe name>;
 *       server 127.0.0.1:12443 priority=2 probe=<path_probe name>;
 *       degrade_rtt_ratio  1.8;   # ewma/baseline ratio -> DEGRADED
 *       degrade_fail_pct   20;    # probe failure % (last 32) -> DEGRADED
 *       down_fail_streak   3;     # consecutive probe failures -> DOWN
 *       sustain            3;     # consecutive bad evals -> leave UP
 *       failback           120s;  # healthy duration to regain UP
 *   }
 *
 * Why mode=tls exists: a local tunnel listener (e.g. cloudflared) accepts
 * TCP instantly no matter what happens beyond it, so bare connect proves
 * nothing.  A TLS probe pushes a ClientHello through the whole path and
 * waits for the first response byte.  For pure direct paths, mode=tcp
 * (SYN -> SYN-ACK) measures exactly the segment in question and depends
 * on nothing at the far end.
 *
 * State machine (evaluated by the leader after every probe):
 *
 *   UP        -toolgit ok, metrics within thresholds
 *   DEGRADED  - sustained (sustain) ratio/loss breach, not total outage
 *   DOWN      - down_fail_streak consecutive probe failures
 *
 *   UP -> DEGRADED : bad_streak >= sustain
 *   any -> DOWN    : fail_streak >= down_fail_streak
 *   !UP -> UP      : healthy (no bad eval) for >= failback
 *
 * Shared-fate suppression: when every member of a group is bad in the
 * same evaluation, transitions are suppressed (likely the local uplink,
 * not one path) and a notice is logged once.
 *
 * New variables:
 *   $route_member       - chosen member index, "-" if not a group target
 *   $route_member_addr  - chosen member addr:port (raw target when pinned)
 *   $route_member_state - member state at decision time (up|degraded|down|-)
 *   $route_member_rtt   - chosen member's last probe RTT in microseconds
 *
 * (The group name a map produced is already visible through the user's own
 *  map variable; these four describe the *decision*, deliberately under a
 *  "route_member" prefix that is unlikely to collide with map target
 *  names.  A collision produces an explicit config error, never a silent
 *  handler overwrite.)
 *
 * Shared memory: one zone per group ("route_group_<name>") keeps member
 * state across reloads (same name+size+tag reuses the mapping).  A tiny
 * "route_group_leader" zone implements leader election (pid + heartbeat).
 *
 * v1 scope: active probes only (no passive TCP_INFO sampling).
 *
 * Author: cddeppe/nginx fork
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>


#define NGX_RG_MAGIC            0x52475a4d  /* "RGZM" */
#define NGX_RG_HIST_LEN         32
#define NGX_RG_MAX_MEMBERS      16
#define NGX_RG_LEADER_STALE     1000        /* ms without beat -> takeover */
#define NGX_RG_WATCHDOG_TICK    1000        /* ms */
#define NGX_RG_ZONE_SIZE        (8 * ngx_pagesize)  /* fixed: reuse across reloads */

#define NGX_RG_STATE_UP         0
#define NGX_RG_STATE_DEGRADED   1
#define NGX_RG_STATE_DOWN       2

#define NGX_RG_MODE_TCP         0
#define NGX_RG_MODE_TLS         1


/* ------------------------------------------------------------------ */
/* config-time structures                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_str_t          name;
    ngx_addr_t        *addr;          /* single addr, parsed */
    ngx_str_t          addr_text;
    ngx_str_t          sni;
    ngx_uint_t         mode;
    ngx_msec_t         interval;
    ngx_msec_t         timeout;
    u_char             ch[160];       /* prebuilt ClientHello (mode=tls) */
    ngx_uint_t         ch_len;
} rg_probe_t;


typedef struct {
    ngx_str_t          name;          /* probe name, resolved post-parse */
    ngx_addr_t        *addr;
    ngx_str_t          addr_text;     /* substituted into proxy_pass */
    ngx_uint_t         priority;      /* lower wins; 0 = auto (order) */
    ngx_uint_t         orig_index;
    ngx_uint_t         shm_index;     /* index after priority sort */
    rg_probe_t        *probe;         /* NULL = never probed, always UP */
} rg_member_t;


typedef struct {
    ngx_str_t          name;
    ngx_array_t        members;       /* rg_member_t */
    ngx_uint_t         rtt_ratio_x100;   /* default 180 = 1.8 */
    ngx_uint_t         fail_pct;         /* default 20 */
    ngx_uint_t         down_fail_streak; /* default 3 */
    ngx_uint_t         sustain;          /* default 3 */
    ngx_msec_t         failback;         /* default 120s */
    ngx_shm_zone_t    *zone;
    void              *shm;           /* rg_group_shm_t * (mapped) */
} rg_group_t;


typedef struct {
    ngx_int_t          path;          /* member idx, -1 = not a group */
    ngx_str_t          member_addr;   /* chosen member addr (or raw target) */
    ngx_uint_t         state;         /* member state at decision time */
    ngx_msec_t         rtt;           /* last probe rtt, usec */
} rg_ctx_t;


typedef struct {
    ngx_array_t        probes;        /* rg_probe_t */
    ngx_array_t        groups;        /* rg_group_t */
    ngx_shm_zone_t    *leader_zone;
    void              *leader_shm;    /* rg_leader_shm_t * (slab alloc) */
} rg_main_conf_t;


/* ------------------------------------------------------------------ */
/* shared-memory structures                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_atomic_t       state;         /* NGX_RG_STATE_* */
    ngx_atomic_t       rtt_ewma;      /* usec */
    ngx_atomic_t       rtt_baseline;  /* usec, slow-adapting min */
    ngx_atomic_t       rtt_last;      /* usec */
    ngx_atomic_t       hist;          /* last 32 probes, bit0 = latest, 1 = ok */
    ngx_atomic_t       fail_streak;   /* consecutive probe failures */
    ngx_atomic_t       bad_streak;    /* consecutive bad evaluations */
    ngx_atomic_t       good_since;    /* msec start of healthy streak, 0 = none */
    ngx_atomic_t       last_change;   /* msec of last state change */
    ngx_atomic_t       probes_done;
} rg_member_shm_t;


typedef struct {
    ngx_atomic_t       magic;
    ngx_atomic_t       layout;        /* hash: name + member addrs */
    ngx_atomic_t       nmembers;
    ngx_atomic_t       shared_fate;   /* boolean flag */
    rg_member_shm_t    members[1];
} rg_group_shm_t;


typedef struct {
    ngx_atomic_t       leader_pid;
    ngx_atomic_t       beat;          /* ngx_current_msec heartbeat */
} rg_leader_shm_t;


/* ------------------------------------------------------------------ */
/* worker-local runtime (leader only probes)                          */
/* ------------------------------------------------------------------ */

typedef struct {
    rg_group_t        *g;
    rg_member_t       *m;
    ngx_event_t        timer;         /* interval timer */
    ngx_peer_connection_t pc;
    ngx_msec_t         t0;            /* current probe start */
    ngx_uint_t         active;
    ngx_uint_t         sent;          /* ClientHello bytes sent */
} rg_probe_rt_t;


static ngx_int_t ngx_stream_route_group_init(ngx_conf_t *cf);
static void *ngx_stream_route_group_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_route_group_path_probe(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_route_group_path_probe_line(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);
static char *ngx_stream_route_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_route_group_line(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static ngx_int_t ngx_stream_route_group_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_stream_route_group_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_stream_route_group_init_leader_zone(
    ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_stream_route_group_member_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_route_group_member_addr_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_route_group_member_state_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_route_group_member_rtt_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);

static void rg_watchdog(ngx_event_t *ev);
static void rg_probe_timer(ngx_event_t *ev);
static void rg_probe_start(rg_probe_rt_t *rt);
static void rg_probe_connected(ngx_event_t *wev);
static void rg_probe_send(ngx_event_t *wev);
static void rg_probe_readable(ngx_event_t *rev);
static void rg_probe_finish(rg_probe_rt_t *rt, ngx_uint_t ok,
    ngx_msec_t rtt_usec);
static void rg_evaluate_group(rg_group_t *g);

/* this fork's ngx_event_connect_peer() calls pc->get() unconditionally */
static ngx_int_t rg_probe_get_peer(ngx_peer_connection_t *pc, void *data);

static ngx_int_t
rg_probe_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static ngx_command_t  ngx_stream_route_group_commands[] = {
    { ngx_string("path_probe"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_route_group_path_probe,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("route_group"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_route_group,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_route_group_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_stream_route_group_init,            /* postconfiguration */
    ngx_stream_route_group_create_main_conf,/* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL                                    /* merge server configuration */
};


ngx_module_t  ngx_stream_route_group_module = {
    NGX_MODULE_V1,
    &ngx_stream_route_group_module_ctx,     /* module context */
    ngx_stream_route_group_commands,        /* module directives */
    NGX_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_stream_route_group_init_process,    /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


/* worker-local state (reset by fork from the master) */
static rg_leader_shm_t  *rg_leader_shm = NULL;
static ngx_event_t        rg_watchdog_ev;
static ngx_event_t       *rg_probe_evs = NULL;   /* [total members] */
static rg_probe_rt_t     *rg_probe_rts = NULL;
static ngx_uint_t         rg_total_members = 0;
static ngx_uint_t         rg_probes_armed = 0;
static ngx_uint_t         rg_is_leader = 0;


/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static ngx_inline ngx_uint_t
rg_popcount32(uint32_t v)
{
#if (NGX_HAVE_GCC_BUILTIN_POPCOUNT)
    return (ngx_uint_t) __builtin_popcount(v);
#else
    ngx_uint_t  n = 0;
    while (v) { v &= v - 1; n++; }
    return n;
#endif
}


static u_char *
rg_state_name(ngx_uint_t state)
{
    switch (state) {
    case NGX_RG_STATE_UP:       return (u_char *) "up";
    case NGX_RG_STATE_DEGRADED: return (u_char *) "degraded";
    case NGX_RG_STATE_DOWN:     return (u_char *) "down";
    default:                    return (u_char *) "?";
    }
}


static ngx_uint_t
rg_layout_hash(rg_group_t *g)
{
    ngx_uint_t   i, h;
    rg_member_t *ms;

    h = 2166136261u;  /* fnv-1a offset */
    for (i = 0; i < g->name.len; i++) {
        h = (h ^ g->name.data[i]) * 16777619;
    }
    ms = g->members.elts;
    for (i = 0; i < g->members.nelts; i++) {
        h = (h ^ g->members.nelts) * 16777619;
        for (ngx_uint_t j = 0; j < ms[i].addr_text.len; j++) {
            h = (h ^ ms[i].addr_text.data[j]) * 16777619;
        }
    }
    return h;
}


static char *
rg_parse_ratio(ngx_str_t *value, ngx_uint_t *x100)
{
    u_char      *p, *last, *dot;
    ngx_uint_t   whole, frac, digits;

    p = value->data;
    last = p + value->len;

    dot = NULL;
    for (u_char *q = p; q < last; q++) {
        if (*q == '.') {
            if (dot) return "invalid value";
            dot = q;
        } else if (*q < '0' || *q > '9') {
            return "invalid value";
        }
    }

    whole = 0;
    for (; p < (dot ? dot : last); p++) {
        whole = whole * 10 + (*p - '0');
        if (whole > 100000) return "value too large";
    }

    frac = 0;
    digits = 0;
    if (dot) {
        for (p = dot + 1; p < last; p++) {
            if (++digits > 2) return "at most two fractional digits";
            frac = frac * 10 + (*p - '0');
        }
    }
    if (digits == 1) frac *= 10;

    *x100 = whole * 100 + frac;
    if (*x100 < 100) return "ratio must be >= 1.0";
    return NULL;
}


static ngx_int_t
rg_build_client_hello(rg_probe_t *probe)
{
    /*
     * Minimal TLS 1.2 ClientHello with server_name + signature_algorithms:
     *
     *   16 03 01 LL LL               TLS record (handshake)
     *   01 00 00 LL                  ClientHello
     *   03 03                        client_version TLS 1.2
     *   <32 random>
     *   00                           session_id length
     *   00 04 c0 2f c0 2b            ciphers: ECDHE-(RSA|ECDSA)-AES128-GCM
     *   01 00                        compression: null
     *   LL LL                        extensions length
     *   00 00 LL LL LL LL 00 LL LL <sni>        server_name extension
     *   00 0d 00 06 00 02 04 03 04 01           signature_algorithms
     *
     * The server_name encoding is byte-exact per RFC 6066: a conformant
     * parser (nginx ssl_preread included) must extract probe->sni from
     * it.  The ciphers are ECDHE-GCM so modern origins answer with a
     * ServerHello rather than a handshake alert (RSA key exchange is
     * refused by most CDNs today).
     */
    u_char    *p = probe->ch;
    size_t     sni_len = probe->sni.len;
    size_t     sni_body, sig_body, exts_len, body_len, total;
    u_char    *ext_len_p, *body_len_p, *rec_len_p;
    ngx_uint_t i;

    sni_body = 5 + sni_len;            /* list_len + type + name_len + name */
    sig_body = 6;                      /* count + 2 signature algorithms */
    exts_len = (4 + sni_body) + (4 + sig_body);
    body_len = 2 + 32 + 1 + 2 + 4 + 2 + 2 + exts_len;
    total = 5 + 4 + body_len;

    if (total > sizeof(probe->ch)) {
        return NGX_ERROR;
    }

    /* random: config-time constants are fine (probe only, not a session) */
    static u_char rnd[32] = {
        0x41,0x37,0x6b,0x2c,0x91,0x55,0xd8,0x0e, 0x6a,0xf4,0x22,0x8e,
        0x17,0xd0,0xa3,0xbb, 0x50,0x29,0x7c,0x66, 0xd1,0x9f,0x34,0xa8,
        0xc2,0x60,0x11,0x7d, 0x0b,0xe4,0x83,0x25
    };

    *p++ = 0x16; *p++ = 0x03; *p++ = 0x01;
    rec_len_p = p; p += 2;                        /* record length, fill later */

    *p++ = 0x01;
    body_len_p = p; p += 3;                       /* handshake length */

    *p++ = 0x03; *p++ = 0x03;
    for (i = 0; i < 32; i++) *p++ = rnd[i];
    *p++ = 0x00;                                  /* session id */
    *p++ = 0x00; *p++ = 0x04;
    *p++ = 0xc0; *p++ = 0x2f;         /* ECDHE-RSA-AES128-GCM-SHA256 */
    *p++ = 0xc0; *p++ = 0x2b;         /* ECDHE-ECDSA-AES128-GCM-SHA256 */
    *p++ = 0x01; *p++ = 0x00;                     /* compression */
    ext_len_p = p; p += 2;                        /* extensions length */

    /* server_name extension (RFC 6066):
     *   uint16 ext_body_len; uint16 list_len; uint8 type; uint16 name_len;
     *   name */
    *p++ = 0x00; *p++ = 0x00;
    *p++ = (u_char) (sni_body >> 8);
    *p++ = (u_char) (sni_body & 0xff);
    *p++ = (u_char) ((sni_len + 3) >> 8);
    *p++ = (u_char) ((sni_len + 3) & 0xff);
    *p++ = 0x00;
    *p++ = (u_char) (sni_len >> 8);
    *p++ = (u_char) (sni_len & 0xff);
    for (i = 0; i < sni_len; i++) *p++ = probe->sni.data[i];

    /* signature_algorithms extension (needed for TLS 1.2 ECDHE) */
    *p++ = 0x00; *p++ = 0x0d;
    *p++ = 0x00; *p++ = 0x06;
    *p++ = 0x00; *p++ = 0x02;
    *p++ = 0x04; *p++ = 0x03;         /* ecdsa_secp256r1_sha256 */
    *p++ = 0x04; *p++ = 0x01;         /* rsa_pkcs1_sha256 */

    /* fill lengths */
    body_len = (size_t) (p - body_len_p - 3);
    body_len_p[0] = (u_char) (body_len >> 16);
    body_len_p[1] = (u_char) (body_len >> 8);
    body_len_p[2] = (u_char) (body_len & 0xff);

    ext_len_p[0] = (u_char) (exts_len >> 8);
    ext_len_p[1] = (u_char) (exts_len & 0xff);

    total = (size_t) (p - rec_len_p - 2);
    rec_len_p[0] = (u_char) (total >> 8);
    rec_len_p[1] = (u_char) (total & 0xff);

    probe->ch_len = (ngx_uint_t) (p - probe->ch);

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* main configuration                                                 */
/* ------------------------------------------------------------------ */

static void *
ngx_stream_route_group_create_main_conf(ngx_conf_t *cf)
{
    rg_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(rg_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&mcf->probes, cf->pool, 4, sizeof(rg_probe_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&mcf->groups, cf->pool, 4, sizeof(rg_group_t))
        != NGX_OK)
    {
        return NULL;
    }

    return mcf;
}


/* ------------------------------------------------------------------ */
/* path_probe { ... } block                                           */
/* ------------------------------------------------------------------ */

static char *
ngx_stream_route_group_path_probe(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    rg_main_conf_t *mcf = conf;
    ngx_str_t      *value;
    rg_probe_t     *probe, *probes;
    ngx_uint_t      i;
    ngx_conf_t      save;
    char           *rv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid path_probe name");
        return NGX_CONF_ERROR;
    }

    probes = mcf->probes.elts;
    for (i = 0; i < mcf->probes.nelts; i++) {
        if (probes[i].name.len == value[1].len
            && ngx_strncmp(probes[i].name.data, value[1].data, value[1].len)
               == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate path_probe \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    probe = ngx_array_push(&mcf->probes);
    if (probe == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(probe, sizeof(rg_probe_t));

    probe->name.data = ngx_pstrdup(cf->pool, &value[1]);
    if (probe->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    probe->name.len = value[1].len;

    probe->mode = NGX_RG_MODE_TCP;
    probe->interval = 1000;
    probe->timeout = 3000;

    save = *cf;
    cf->handler = ngx_stream_route_group_path_probe_line;
    cf->handler_conf = probe;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (probe->addr == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "path_probe \"%V\" requires a \"target\" directive",
                           &probe->name);
        return NGX_CONF_ERROR;
    }

    if (probe->mode == NGX_RG_MODE_TLS) {
        if (probe->sni.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "path_probe \"%V\": mode tls requires \"sni\"",
                               &probe->name);
            return NGX_CONF_ERROR;
        }
        if (rg_build_client_hello(probe) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "path_probe \"%V\": sni too long",
                               &probe->name);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_route_group_path_probe_line(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf)
{
    rg_probe_t  *probe = conf;
    ngx_str_t   *value;
    ngx_url_t    u;
    ngx_int_t    t;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {
        goto invalid;
    }

    if (ngx_strcmp(value[0].data, "target") == 0) {

        if (cf->args->nelts != 2 || probe->addr != NULL) {
            goto invalid;
        }

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.no_resolve = 1;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK
            || u.addrs == NULL || u.naddrs != 1)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "path_probe \"%V\": target must be an "
                               "IP:port literal (hostnames are not resolved)",
                               &probe->name);
            return NGX_CONF_ERROR;
        }

        probe->addr = u.addrs;

        probe->addr_text.data = ngx_pstrdup(cf->pool, &value[1]);
        if (probe->addr_text.data == NULL) {
            return NGX_CONF_ERROR;
        }
        probe->addr_text.len = value[1].len;

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "sni") == 0) {

        if (cf->args->nelts != 2 || probe->sni.len != 0) {
            goto invalid;
        }
        if (value[1].len > 63) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "path_probe \"%V\": sni too long (max 63)",
                               &probe->name);
            return NGX_CONF_ERROR;
        }

        probe->sni.data = ngx_pstrdup(cf->pool, &value[1]);
        if (probe->sni.data == NULL) {
            return NGX_CONF_ERROR;
        }
        probe->sni.len = value[1].len;

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "mode") == 0) {

        if (cf->args->nelts != 2) {
            goto invalid;
        }
        if (ngx_strcmp(value[1].data, "tcp") == 0) {
            probe->mode = NGX_RG_MODE_TCP;
        } else if (ngx_strcmp(value[1].data, "tls") == 0) {
            probe->mode = NGX_RG_MODE_TLS;
        } else {
            goto invalid;
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "interval") == 0
        || ngx_strcmp(value[0].data, "timeout") == 0)
    {
        if (cf->args->nelts != 2) {
            goto invalid;
        }

        t = ngx_parse_time(&value[1], 0);
        if (t == NGX_ERROR || t == 0) {
            goto invalid;
        }

        if (value[0].data[0] == 'i') {
            probe->interval = (ngx_msec_t) t;
        } else {
            probe->timeout = (ngx_msec_t) t;
        }

        return NGX_CONF_OK;
    }

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid directive in path_probe \"%V\": "
                       "\"target <ip:port>|sni <name>|mode tcp|tls|"
                       "interval <time>|timeout <time>\" expected",
                       &probe->name);
    return NGX_CONF_ERROR;
}


/* ------------------------------------------------------------------ */
/* route_group { ... } block                                          */
/* ------------------------------------------------------------------ */

static char *
ngx_stream_route_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    rg_main_conf_t *mcf = conf;
    ngx_str_t      *value, zname;
    rg_group_t     *group, *groups;
    ngx_uint_t      i;
    ngx_conf_t      save;
    char           *rv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid route_group name");
        return NGX_CONF_ERROR;
    }

    groups = mcf->groups.elts;
    for (i = 0; i < mcf->groups.nelts; i++) {
        if (groups[i].name.len == value[1].len
            && ngx_strncmp(groups[i].name.data, value[1].data, value[1].len)
               == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate route_group \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    group = ngx_array_push(&mcf->groups);
    if (group == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(group, sizeof(rg_group_t));

    group->name.data = ngx_pstrdup(cf->pool, &value[1]);
    if (group->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    group->name.len = value[1].len;

    group->rtt_ratio_x100 = 180;    /* 1.8 */
    group->fail_pct = 20;
    group->down_fail_streak = 3;
    group->sustain = 3;
    group->failback = 120000;

    if (ngx_array_init(&group->members, cf->pool, 4, sizeof(rg_member_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_stream_route_group_line;
    cf->handler_conf = group;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (group->members.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "route_group \"%V\" has no members",
                           &group->name);
        return NGX_CONF_ERROR;
    }

    if (group->members.nelts > NGX_RG_MAX_MEMBERS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "route_group \"%V\" supports at most %ud members",
                           &group->name, NGX_RG_MAX_MEMBERS);
        return NGX_CONF_ERROR;
    }

    /* register the per-group shared memory zone.  Fixed size (8 pages)
     * so the mapping is reused across reloads regardless of member
     * count; a layout hash inside the state detects semantic changes
     * and resets state when needed. */
    zname.len = sizeof("route_group_") - 1 + group->name.len;
    zname.data = ngx_pnalloc(cf->pool, zname.len);
    if (zname.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(zname.data, "route_group_", sizeof("route_group_") - 1);
    ngx_memcpy(zname.data + sizeof("route_group_") - 1,
               group->name.data, group->name.len);

    group->zone = ngx_shared_memory_add(cf, &zname, NGX_RG_ZONE_SIZE,
                                        &ngx_stream_route_group_module);
    if (group->zone == NULL) {
        return NGX_CONF_ERROR;
    }
    group->zone->init = ngx_stream_route_group_init_zone;
    group->zone->data = group;

    return NGX_CONF_OK;
}


static char *
ngx_stream_route_group_line(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    rg_group_t  *group = conf;
    ngx_str_t   *value, *p;
    rg_member_t *member;
    ngx_uint_t   i, nelts;
    ngx_url_t    u;
    ngx_int_t    n, t;
    char        *rc;

    value = cf->args->elts;
    nelts = cf->args->nelts;

    if (nelts == 1) {
        goto invalid;
    }

    if (ngx_strcmp(value[0].data, "server") == 0) {

        if (group->members.nelts >= NGX_RG_MAX_MEMBERS) {
            goto invalid;
        }

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.no_resolve = 1;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK
            || u.addrs == NULL || u.naddrs != 1)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "route_group \"%V\": server target must be an "
                               "IP:port literal", &group->name);
            return NGX_CONF_ERROR;
        }

        member = ngx_array_push(&group->members);
        if (member == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memzero(member, sizeof(rg_member_t));

        member->addr = u.addrs;
        member->orig_index = group->members.nelts - 1;

        member->addr_text.data = ngx_pstrdup(cf->pool, &value[1]);
        if (member->addr_text.data == NULL) {
            return NGX_CONF_ERROR;
        }
        member->addr_text.len = value[1].len;

        /* optional parameters: priority=N probe=name */
        for (i = 2; i < nelts; i++) {
            if (value[i].len > 9
                && ngx_strncmp(value[i].data, "priority=", 9) == 0)
            {
                p = &value[i];
                p->data += 9;
                p->len -= 9;

                n = ngx_atoi(p->data, p->len);
                if (n == NGX_ERROR || n == 0) {
                    goto invalid;
                }
                member->priority = (ngx_uint_t) n;

            } else if (value[i].len > 6
                       && ngx_strncmp(value[i].data, "probe=", 6) == 0)
            {
                member->name.len = value[i].len - 6;
                member->name.data = ngx_pnalloc(cf->pool, member->name.len);
                if (member->name.data == NULL) {
                    return NGX_CONF_ERROR;
                }
                ngx_memcpy(member->name.data, value[i].data + 6,
                           member->name.len);

            } else {
                goto invalid;
            }
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "degrade_rtt_ratio") == 0) {
        if (nelts != 2) {
            goto invalid;
        }
        rc = rg_parse_ratio(&value[1], &group->rtt_ratio_x100);
        if (rc != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "route_group \"%V\": degrade_rtt_ratio %s",
                               &group->name, rc);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "degrade_fail_pct") == 0
        || ngx_strcmp(value[0].data, "down_fail_streak") == 0
        || ngx_strcmp(value[0].data, "sustain") == 0)
    {
        if (nelts != 2) {
            goto invalid;
        }
        n = ngx_atoi(value[1].data, value[1].len);
        if (n == NGX_ERROR || n == 0) {
            goto invalid;
        }
        if (value[0].data[8] == 'f') {          /* degrade_fail_pct */
            group->fail_pct = (ngx_uint_t) n;
        } else if (value[0].data[0] == 'd') {   /* down_fail_streak */
            group->down_fail_streak = (ngx_uint_t) n;
        } else {                                /* sustain */
            group->sustain = (ngx_uint_t) n;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "failback") == 0) {
        if (nelts != 2) {
            goto invalid;
        }
        t = ngx_parse_time(&value[1], 0);
        if (t == NGX_ERROR || t < 1000) {
            goto invalid;
        }
        group->failback = (ngx_msec_t) t;
        return NGX_CONF_OK;
    }

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid directive in route_group \"%V\"",
                       &group->name);
    return NGX_CONF_ERROR;
}


/* ------------------------------------------------------------------ */
/* shared memory zone init (runs in the master, before workers fork)  */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_route_group_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    rg_group_t      *g = shm_zone->data;
    rg_group_t      *og = data;
    ngx_slab_pool_t *sp;
    rg_group_shm_t  *sh;
    ngx_uint_t       i, layout, size;

    layout = rg_layout_hash(g);
    size = sizeof(rg_group_shm_t)
           + (g->members.nelts - 1) * sizeof(rg_member_shm_t);

    if (og != NULL && og->shm != NULL) {
        /* zone reused across reload: keep state when the layout matches */
        sh = (rg_group_shm_t *) og->shm;

        if (sh->magic == NGX_RG_MAGIC
            && sh->nmembers == g->members.nelts
            && sh->layout == layout)
        {
            g->shm = sh;
            return NGX_OK;
        }

        /* layout changed: reset the struct in place (same allocation) */
        ngx_memzero(sh, size);

    } else {
        /* fresh zone: allocate the state struct from the slab pool */
        sp = (ngx_slab_pool_t *) shm_zone->shm.addr;

        sh = ngx_slab_alloc(sp, size);
        if (sh == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(sh, size);
    }

    sh->magic = NGX_RG_MAGIC;
    sh->layout = layout;
    sh->nmembers = g->members.nelts;

    /* fresh state: UP, no samples yet */
    for (i = 0; i < g->members.nelts; i++) {
        sh->members[i].state = NGX_RG_STATE_UP;
    }

    g->shm = sh;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_route_group_init_leader_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    rg_main_conf_t  *mcf = shm_zone->data;
    rg_main_conf_t  *omcf = data;
    ngx_slab_pool_t *sp;
    rg_leader_shm_t *lz;

    if (omcf != NULL && omcf->leader_shm != NULL) {
        /* reload: reuse the slab-allocated leader record.  The old leader
         * keeps beating while it drains; once it exits the beat goes stale
         * and a new worker claims leadership within NGX_RG_LEADER_STALE. */
        mcf->leader_shm = omcf->leader_shm;
        return NGX_OK;
    }

    sp = (ngx_slab_pool_t *) shm_zone->shm.addr;

    lz = ngx_slab_alloc(sp, sizeof(rg_leader_shm_t));
    if (lz == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(lz, sizeof(rg_leader_shm_t));
    mcf->leader_shm = lz;

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* postconfiguration                                                  */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_route_group_init(ngx_conf_t *cf)
{
    rg_main_conf_t     *mcf;
    rg_group_t         *groups;
    rg_member_t        *ms, tmp;
    rg_probe_t         *probes;
    ngx_uint_t          gi, mi, pi, j, k;
    ngx_shm_zone_t     *zone;
    ngx_str_t           zname;
    ngx_stream_variable_t *v;

    static ngx_str_t  var_member = ngx_string("route_member");
    static ngx_str_t  var_member_addr = ngx_string("route_member_addr");
    static ngx_str_t  var_member_state = ngx_string("route_member_state");
    static ngx_str_t  var_member_rtt = ngx_string("route_member_rtt");

    mcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_route_group_module);

    /* register variables unconditionally so log_format references are
     * always valid, even when no groups are configured */
    v = ngx_stream_add_variable(cf, &var_member, 0);
    if (v == NULL || v->get_handler != NULL) {
        return NGX_ERROR;
    }
    v->get_handler = ngx_stream_route_group_member_variable;

    v = ngx_stream_add_variable(cf, &var_member_addr, 0);
    if (v == NULL || v->get_handler != NULL) {
        return NGX_ERROR;
    }
    v->get_handler = ngx_stream_route_group_member_addr_variable;

    v = ngx_stream_add_variable(cf, &var_member_state, 0);
    if (v == NULL || v->get_handler != NULL) {
        return NGX_ERROR;
    }
    v->get_handler = ngx_stream_route_group_member_state_variable;

    v = ngx_stream_add_variable(cf, &var_member_rtt, 0);
    if (v == NULL || v->get_handler != NULL) {
        return NGX_ERROR;
    }
    v->get_handler = ngx_stream_route_group_member_rtt_variable;

    if (mcf == NULL || mcf->groups.nelts == 0) {
        return NGX_OK;
    }

    groups = mcf->groups.elts;
    probes = mcf->probes.elts;

    for (gi = 0; gi < mcf->groups.nelts; gi++) {

        ms = groups[gi].members.elts;

        /* resolve probe references */
        for (mi = 0; mi < groups[gi].members.nelts; mi++) {
            if (ms[mi].name.len == 0) {
                continue;
            }
            for (pi = 0; pi < mcf->probes.nelts; pi++) {
                if (probes[pi].name.len == ms[mi].name.len
                    && ngx_strncmp(probes[pi].name.data, ms[mi].name.data,
                                   ms[mi].name.len) == 0)
                {
                    ms[mi].probe = &probes[pi];
                    break;
                }
            }
            if (ms[mi].probe == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "route_group \"%V\": member \"%V\" "
                                   "references unknown path_probe \"%V\"",
                                   &groups[gi].name, &ms[mi].addr_text,
                                   &ms[mi].name);
                return NGX_ERROR;
            }
        }

        /* default priorities follow declaration order */
        for (mi = 0; mi < groups[gi].members.nelts; mi++) {
            if (ms[mi].priority == 0) {
                ms[mi].priority = ms[mi].orig_index + 1;
            }
        }

        /* stable insertion sort by priority (ties keep declaration order) */
        for (j = 1; j < groups[gi].members.nelts; j++) {
            tmp = ms[j];
            for (k = j; k > 0; k--) {
                if (ms[k - 1].priority <= tmp.priority) {
                    break;
                }
                ms[k] = ms[k - 1];
            }
            ms[k] = tmp;
        }

        /* shm slot index == position after sort */
        for (mi = 0; mi < groups[gi].members.nelts; mi++) {
            ms[mi].shm_index = mi;
        }
    }

    /* leader-election zone (one, shared by all groups) */
    zname.len = sizeof("route_group_leader") - 1;
    zname.data = (u_char *) "route_group_leader";

    zone = ngx_shared_memory_add(cf, &zname, NGX_RG_ZONE_SIZE,
                                 &ngx_stream_route_group_module);
    if (zone == NULL) {
        return NGX_ERROR;
    }
    zone->init = ngx_stream_route_group_init_leader_zone;
    zone->data = mcf;
    mcf->leader_zone = zone;

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* runtime: init_process, watchdog, leader election                   */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_route_group_init_process(ngx_cycle_t *cycle)
{
    rg_main_conf_t        *mcf;
    ngx_stream_conf_ctx_t *sctx;
    rg_group_t            *groups;
    rg_member_t           *ms;
    ngx_uint_t             gi, mi, idx;

    sctx = (ngx_stream_conf_ctx_t *)
               ngx_get_conf(cycle->conf_ctx, ngx_stream_module);

    if (sctx == NULL) {
        return NGX_OK;
    }

    mcf = sctx->main_conf[ngx_stream_route_group_module.ctx_index];
    if (mcf == NULL || mcf->groups.nelts == 0) {
        return NGX_OK;
    }

    rg_leader_shm = (rg_leader_shm_t *) mcf->leader_shm;
    if (rg_leader_shm == NULL) {
        return NGX_OK;
    }

    /* flatten all groups' members into worker-local probe runtime */
    groups = mcf->groups.elts;
    rg_total_members = 0;
    for (gi = 0; gi < mcf->groups.nelts; gi++) {
        rg_total_members += groups[gi].members.nelts;
    }

    rg_probe_evs = ngx_pcalloc(cycle->pool,
                               rg_total_members * sizeof(ngx_event_t));
    rg_probe_rts = ngx_pcalloc(cycle->pool,
                               rg_total_members * sizeof(rg_probe_rt_t));
    if (rg_probe_evs == NULL || rg_probe_rts == NULL) {
        return NGX_ERROR;
    }

    idx = 0;
    for (gi = 0; gi < mcf->groups.nelts; gi++) {
        ms = groups[gi].members.elts;
        for (mi = 0; mi < groups[gi].members.nelts; mi++) {
            rg_probe_rts[idx].g = &groups[gi];
            rg_probe_rts[idx].m = &ms[mi];
            rg_probe_evs[idx].handler = rg_probe_timer;
            rg_probe_evs[idx].data = &rg_probe_rts[idx];
            rg_probe_evs[idx].log = cycle->log;
            idx++;
        }
    }

    ngx_memzero(&rg_watchdog_ev, sizeof(ngx_event_t));
    rg_watchdog_ev.handler = rg_watchdog;
    rg_watchdog_ev.log = cycle->log;
    rg_watchdog_ev.data = NULL;

    /* first watchdog tick runs immediately after the event loop starts;
     * use a 1ms delay so it fires from the timer wheel, not inline */
    rg_probes_armed = 0;
    rg_is_leader = 0;

    ngx_add_timer(&rg_watchdog_ev, 1);

    return NGX_OK;
}


static void
rg_watchdog(ngx_event_t *ev)
{
    ngx_atomic_uint_t  cur;

    if (rg_leader_shm == NULL) {
        return;
    }

    cur = rg_leader_shm->leader_pid;

    if (cur == (ngx_atomic_uint_t) ngx_pid) {
        rg_is_leader = 1;

    } else if (cur == 0) {
        if (ngx_atomic_cmp_set(&rg_leader_shm->leader_pid, 0,
                               (ngx_atomic_uint_t) ngx_pid))
        {
            rg_is_leader = 1;
        }

    } else if ((ngx_msec_int_t) (ngx_current_msec
                - (ngx_msec_t) rg_leader_shm->beat) > NGX_RG_LEADER_STALE)
    {
        /* leader died (crash or reload-drain exit): take over */
        if (ngx_atomic_cmp_set(&rg_leader_shm->leader_pid, cur,
                               (ngx_atomic_uint_t) ngx_pid))
        {
            rg_is_leader = 1;
        }

    } else if (rg_is_leader) {
        /* demoted (a new leader claimed after a reload): stop probing */
        rg_is_leader = 0;
    }

    if (rg_is_leader) {
        rg_leader_shm->beat = ngx_current_msec;

        if (!rg_probes_armed && rg_probe_evs != NULL) {
            ngx_uint_t  i;
            for (i = 0; i < rg_total_members; i++) {
                ngx_add_timer(&rg_probe_evs[i], 100 + i * 50);
            }
            rg_probes_armed = 1;

            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "route_group: worker pid %P elected probe leader "
                          "(%ui members)", ngx_pid, rg_total_members);
        }
    }

    ngx_add_timer(ev, NGX_RG_WATCHDOG_TICK);
}


/* ------------------------------------------------------------------ */
/* runtime: probe machinery                                           */
/* ------------------------------------------------------------------ */

static void
rg_probe_timer(ngx_event_t *ev)
{
    rg_probe_rt_t *rt = ev->data;

    if (rt->m->probe != NULL) {
        ngx_add_timer(ev, rt->m->probe->interval);
    } else {
        ngx_add_timer(ev, 60000);   /* unprobed member: idle tick */
        return;
    }

    if (!rg_is_leader || rt->active) {
        return;
    }

    rg_probe_start(rt);
}


static void
rg_probe_start(rg_probe_rt_t *rt)
{
    ngx_int_t               rc;
    ngx_connection_t       *c;
    ngx_peer_connection_t  *pc;
    rg_probe_t             *p = rt->m->probe;

    rt->active = 1;
    rt->sent = 0;
    rt->t0 = ngx_current_msec;

    pc = &rt->pc;
    ngx_memzero(pc, sizeof(ngx_peer_connection_t));

    pc->sockaddr = p->addr->sockaddr;
    pc->socklen = p->addr->socklen;
    pc->name = &p->addr_text;
    pc->tries = 1;
    pc->type = SOCK_STREAM;
    pc->get = rg_probe_get_peer;
    pc->log = ngx_cycle->log;

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_BUSY) {
        rg_probe_finish(rt, 0, 0);
        return;
    }

    if (rc == NGX_DECLINED) {
        /* connect() failed synchronously (refused / unreachable) */
        rg_probe_finish(rt, 0, 0);
        return;
    }

    c = pc->connection;
    c->data = rt;
    c->read->handler = rg_probe_readable;
    c->write->handler = rg_probe_connected;

    if (rc == NGX_OK) {
        /* immediate connect (loopback): invoke handler synchronously */
        c->write->timedout = 0;
        rg_probe_connected(c->write);
        return;
    }

    /* NGX_AGAIN */
    ngx_add_timer(c->write, p->timeout);
}


static void
rg_probe_connected(ngx_event_t *wev)
{
    ngx_connection_t  *c = wev->data;
    rg_probe_rt_t     *rt = c->data;
    rg_probe_t        *p = rt->m->probe;
    ssize_t            n;
    int                err;
    socklen_t          len;
    ngx_msec_int_t     remaining;

    if (wev->timedout) {
        rg_probe_finish(rt, 0, 0);
        return;
    }

    len = sizeof(err);
    err = 0;
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
        err = ngx_socket_errno;
    }
    if (err) {
        rg_probe_finish(rt, 0, 0);
        return;
    }

    if (p->mode == NGX_RG_MODE_TCP) {
        rg_probe_finish(rt, 1,
                        (ngx_current_msec - rt->t0) * 1000);
        return;
    }

    /* mode tls: push the ClientHello */
    n = send(c->fd, p->ch + rt->sent, p->ch_len - rt->sent, MSG_NOSIGNAL);

    if (n > 0) {
        rt->sent += n;
    }

    if (rt->sent < p->ch_len) {
        if (n == -1 && ngx_socket_errno != NGX_EAGAIN) {
            rg_probe_finish(rt, 0, 0);
            return;
        }
        wev->handler = rg_probe_send;
        remaining = (ngx_msec_int_t)
                    (p->timeout - (ngx_current_msec - rt->t0));
        if (remaining <= 0) {
            rg_probe_finish(rt, 0, 0);
            return;
        }
        ngx_add_timer(c->read, (ngx_msec_t) remaining);
        return;
    }

    /* fully sent: wait for the first response byte */
    remaining = (ngx_msec_int_t) (p->timeout - (ngx_current_msec - rt->t0));
    if (remaining <= 0) {
        rg_probe_finish(rt, 0, 0);
        return;
    }
    ngx_add_timer(c->read, (ngx_msec_t) remaining);
}


static void
rg_probe_send(ngx_event_t *wev)
{
    ngx_connection_t  *c = wev->data;
    rg_probe_rt_t     *rt = c->data;
    rg_probe_t        *p = rt->m->probe;
    ssize_t            n;

    n = send(c->fd, p->ch + rt->sent, p->ch_len - rt->sent, MSG_NOSIGNAL);

    if (n > 0) {
        rt->sent += n;
    }

    if (rt->sent == p->ch_len) {
        /* done sending; the read timer is already armed */
        return;
    }

    if (n == -1 && ngx_socket_errno != NGX_EAGAIN) {
        rg_probe_finish(rt, 0, 0);
    }
}


static void
rg_probe_readable(ngx_event_t *rev)
{
    ngx_connection_t  *c = rev->data;
    rg_probe_rt_t     *rt = c->data;
    u_char              buf[64];
    ssize_t             n;

    if (rev->timedout) {
        rg_probe_finish(rt, 0, 0);
        return;
    }

    n = recv(c->fd, buf, sizeof(buf), 0);

    if (n > 0) {
        rg_probe_finish(rt, 1, (ngx_current_msec - rt->t0) * 1000);
        return;
    }

    if (n == 0) {
        /* EOF before any byte: path accepted then died (dead tunnel) */
        rg_probe_finish(rt, 0, 0);
        return;
    }

    if (ngx_socket_errno == NGX_EAGAIN || ngx_socket_errno == NGX_EINTR) {
        return;
    }

    rg_probe_finish(rt, 0, 0);
}


static void
rg_probe_finish(rg_probe_rt_t *rt, ngx_uint_t ok, ngx_msec_t rtt_usec)
{
    rg_group_t      *g = rt->g;
    rg_member_t     *m = rt->m;
    rg_group_shm_t  *sh;
    rg_member_shm_t *sm;

    if (rt->pc.connection != NULL) {
        if (rt->pc.connection->read->timer_set) {
            ngx_del_timer(rt->pc.connection->read);
        }
        if (rt->pc.connection->write->timer_set) {
            ngx_del_timer(rt->pc.connection->write);
        }
        ngx_close_connection(rt->pc.connection);
        rt->pc.connection = NULL;
    }

    rt->active = 0;
    rt->sent = 0;

    if (g->shm == NULL) {
        return;
    }

    sh = (rg_group_shm_t *) g->shm;
    sm = &sh->members[m->shm_index];

    if (ok) {
        /*
         * First success after a failure streak: start a fresh window.
         * Resetting here (instead of at the DOWN transition) means the
         * window never fills with fails from an outage that continued
         * past the transition - otherwise a recovering member needs
         * ~NGX_RG_HIST_LEN successes to dilute the failure percentage
         * back under the threshold.
         */
        if (sm->fail_streak > 0) {
            sm->hist = 0;
            sm->probes_done = 0;
        }

        sm->fail_streak = 0;
        sm->hist = (sm->hist << 1) | 1;
        sm->rtt_last = rtt_usec;

        if (sm->rtt_baseline == 0) {
            sm->rtt_baseline = rtt_usec;
            sm->rtt_ewma = rtt_usec;

        } else {
            /*
             * Asymmetric EWMA: slow rise (alpha 1/8, conservative against
             * spikes) but faster decay (alpha 1/3) so a path that recovers
             * after congestion returns below the degrade ratio within a
             * few probe intervals instead of ~3x the rise time.  The
             * sustain/failback hysteresis still guards against flapping.
             */
            if (rtt_usec < sm->rtt_ewma) {
                sm->rtt_ewma = (rtt_usec + 2 * sm->rtt_ewma) / 3;
            } else {
                sm->rtt_ewma = (rtt_usec + 7 * sm->rtt_ewma) / 8;
            }

            if (rtt_usec < sm->rtt_baseline) {
                sm->rtt_baseline = rtt_usec;
            } else {
                sm->rtt_baseline += (rtt_usec - sm->rtt_baseline) / 3600;
            }
        }

    } else {
        sm->fail_streak++;
        sm->hist = sm->hist << 1;
    }

    sm->probes_done++;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "route_group \"%V\" probe %V: %s fail_streak=%ui",
                   &g->name, &m->addr_text, ok ? "ok" : "FAIL",
                   (ngx_uint_t) sm->fail_streak);

    rg_evaluate_group(g);
}


/* ------------------------------------------------------------------ */
/* runtime: health evaluation / state machine                         */
/* ------------------------------------------------------------------ */

static void
rg_evaluate_group(rg_group_t *g)
{
    rg_group_shm_t  *sh;
    rg_member_shm_t *sm;
    ngx_uint_t       n, i, fails_pct, ok_cnt, n_seen;
    ngx_uint_t       bad[NGX_RG_MAX_MEMBERS];
    ngx_uint_t       cand = 0, cand_bad = 0;
    ngx_uint_t       shared_now;
    ngx_msec_t       now = ngx_current_msec;

    if (g->shm == NULL) {
        return;
    }

    sh = (rg_group_shm_t *) g->shm;
    n = (ngx_uint_t) sh->nmembers;

    for (i = 0; i < n; i++) {
        sm = &sh->members[i];

        /* failure percentage over the samples actually observed so far
         * (avoids "all bad" cold-start before the window fills up) */
        n_seen = (ngx_uint_t) sm->probes_done;
        if (n_seen > NGX_RG_HIST_LEN) {
            n_seen = NGX_RG_HIST_LEN;
        }
        ok_cnt = rg_popcount32((uint32_t) sm->hist);
        fails_pct = n_seen ? (n_seen - ok_cnt) * 100 / n_seen : 0;

        bad[i] = (sm->fail_streak > 0)
                 || (fails_pct > g->fail_pct)
                 || (sm->rtt_baseline > 0
                     && sm->rtt_ewma * 100
                        > sm->rtt_baseline * g->rtt_ratio_x100);

        if (sm->state != NGX_RG_STATE_DOWN) {
            cand++;
            if (bad[i]) {
                cand_bad++;
            }
        }
    }

    /*
     * Shared fate means all LIVE members are bad at once (or every
     * member is hard-DOWN).  Members already DOWN do not count toward
     * it: with one path dead and the survivor merely flaky, the
     * flakiness is that member's own signal, not a local-uplink
     * problem - and re-announcing "shared fate" on every flappy eval
     * spams the log and misleads.
     */
    shared_now = (n > 1 && (cand >= 2 || cand == 0) && cand == cand_bad);

    if (shared_now) {
        if (!sh->shared_fate) {
            sh->shared_fate = 1;
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "route_group \"%V\": all live members bad - shared "
                          "fate suspected (local uplink?); DEGRADED "
                          "transitions suppressed, DOWN (hard failures) "
                          "still allowed",
                          &g->name);
        }
        /* fall through: DOWN transitions must still be possible when every
         * member is failing outright - the selector falls back to member 0
         * either way, and an honest DOWN state recovers cleanly */

    } else if (sh->shared_fate) {
        sh->shared_fate = 0;
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                      "route_group \"%V\": shared-fate condition cleared",
                      &g->name);
    }

    for (i = 0; i < n; i++) {
        sm = &sh->members[i];

        if (bad[i]) {
            ngx_uint_t  new_state;

            sm->good_since = 0;
            sm->bad_streak++;

            new_state = (ngx_uint_t) sm->state;

            if (sm->fail_streak >= g->down_fail_streak) {
                new_state = NGX_RG_STATE_DOWN;

            } else if (sm->bad_streak >= g->sustain
                       && sm->state == NGX_RG_STATE_UP && !sh->shared_fate)
            {
                /* metric-breach DEGRADATION is suppressed while every member
                 * is bad (common cause); hard failures still go DOWN above */
                new_state = NGX_RG_STATE_DEGRADED;
            }

            if (new_state != (ngx_uint_t) sm->state) {
                ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                              "route_group \"%V\": member %ui (%V) state "
                              "%s -> %s (ewma=%Mms baseline=%Mms "
                              "fail_streak=%ui)",
                              &g->name, i,
                              &((rg_member_t *) g->members.elts)[i].addr_text,
                              rg_state_name((ngx_uint_t) sm->state),
                              rg_state_name(new_state),
                              sm->rtt_ewma / 1000, sm->rtt_baseline / 1000,
                              (ngx_uint_t) sm->fail_streak);
                sm->state = new_state;
                sm->last_change = now;
            }

        } else {
            sm->bad_streak = 0;

            if (sm->good_since == 0) {
                sm->good_since = now;
            }

            if (sm->state != NGX_RG_STATE_UP
                && now - (ngx_msec_t) sm->good_since >= g->failback)
            {
                ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                              "route_group \"%V\": member %ui (%V) state "
                              "%s -> up (healthy for %Mms)",
                              &g->name, i,
                              &((rg_member_t *) g->members.elts)[i].addr_text,
                              rg_state_name((ngx_uint_t) sm->state),
                              now - (ngx_msec_t) sm->good_since);
                sm->state = NGX_RG_STATE_UP;
                sm->last_change = now;
            }
        }
    }
}


/* ------------------------------------------------------------------ */
/* proxy_pass interception + variables                                */
/* ------------------------------------------------------------------ */

ngx_int_t
ngx_stream_route_group_resolve(ngx_stream_session_t *s, ngx_str_t *in,
    ngx_str_t *out)
{
    rg_main_conf_t  *mcf;
    rg_ctx_t        *ctx;
    rg_group_t      *groups;
    rg_member_t     *ms;
    rg_group_shm_t  *sh;
    ngx_int_t        idx;
    ngx_uint_t       i, gi;

    ctx = ngx_pcalloc(s->connection->pool, sizeof(rg_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->path = -1;
    ctx->member_addr.data = ngx_pnalloc(s->connection->pool, in->len);
    if (ctx->member_addr.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->member_addr.data, in->data, in->len);
    ctx->member_addr.len = in->len;

    ngx_stream_set_ctx(s, ctx, ngx_stream_route_group_module);

    *out = *in;

    mcf = ngx_stream_get_module_main_conf(s, ngx_stream_route_group_module);
    if (mcf == NULL || mcf->groups.nelts == 0) {
        return NGX_OK;
    }

    groups = mcf->groups.elts;

    for (gi = 0; gi < mcf->groups.nelts; gi++) {
        if (groups[gi].name.len != in->len
            || ngx_strncmp(groups[gi].name.data, in->data, in->len) != 0)
        {
            continue;
        }

        /* matched a route_group: pick a member by health */
        ms = groups[gi].members.elts;
        sh = (rg_group_shm_t *) groups[gi].shm;

        idx = -1;

        if (sh != NULL) {
            for (i = 0; i < groups[gi].members.nelts; i++) {
                if ((ngx_uint_t) sh->members[i].state == NGX_RG_STATE_UP) {
                    idx = (ngx_int_t) i;
                    break;
                }
            }

            if (idx == -1) {
                for (i = 0; i < groups[gi].members.nelts; i++) {
                    if ((ngx_uint_t) sh->members[i].state
                        == NGX_RG_STATE_DEGRADED)
                    {
                        idx = (ngx_int_t) i;
                        break;
                    }
                }
            }
        }

        if (idx == -1) {
            /* never blackhole: fall back to the first member */
            idx = 0;
        }

        out->data = ngx_pnalloc(s->connection->pool, ms[idx].addr_text.len);
        if (out->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(out->data, ms[idx].addr_text.data, ms[idx].addr_text.len);
        out->len = ms[idx].addr_text.len;

        ctx->path = idx;
        ctx->member_addr.data = out->data;
        ctx->member_addr.len = out->len;
        if (sh != NULL) {
            ctx->state = (ngx_uint_t) sh->members[idx].state;
            ctx->rtt = (ngx_msec_t) sh->members[idx].rtt_last;
        }

        return NGX_OK;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_route_group_member_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    rg_ctx_t  *ctx;
    u_char    *p;
    size_t     len;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_group_module);
    if (ctx == NULL || ctx->path < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = ngx_sprintf(p, "%i", ctx->path) - p;

    v->data = p;
    v->len = len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_route_group_member_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    rg_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_group_module);
    if (ctx == NULL || ctx->member_addr.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->member_addr.data;
    v->len = ctx->member_addr.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_route_group_member_state_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    rg_ctx_t  *ctx;
    u_char    *name;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_group_module);
    if (ctx == NULL || ctx->path < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    name = rg_state_name(ctx->state);

    v->data = name;
    v->len = ngx_strlen(name);
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_route_group_member_rtt_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    rg_ctx_t  *ctx;
    u_char    *p;
    size_t     len;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_group_module);
    if (ctx == NULL || ctx->path < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = ngx_sprintf(p, "%M", ctx->rtt) - p;

    v->data = p;
    v->len = len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

