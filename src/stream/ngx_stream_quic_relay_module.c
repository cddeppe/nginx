
/*
 * ngx_stream_quic_relay_module.c
 *
 * QUIC-aware UDP relay (DNS-hijack topology) for the nginx stream subsystem.
 *
 * Copyright (C) 2026 cddeppe / xray-quiclink project
 *
 * Design (the "session-NAT" model):
 *
 *   client QUIC --(listen socket, per-addr dispatch by core udp RBTree)-->
 *   [relay] --(per-session CONNECTED upstream socket, stable source port)-->
 *   real QUIC server
 *
 *   - One relay session per client address. Client Initial = (re)birth.
 *   - Replies to the client are sent from the listen socket (sendto),
 *     so the client always sees one stable server address:port.
 *   - Each session owns one connected upstream UDP socket, so the upstream
 *     sees one stable client address:port for the whole connection
 *     (no source-port churn => no visible "migration" to GFE).
 *   - QUIC header parsing is used ONLY for:
 *       * session birth detection (client Initial),
 *       * learning CID lengths (client SCID len / server SCID len),
 *       * registering server CIDs (incl. Retry SCID) in a DCID index,
 *       * optional SNI extraction (Initial decryption, RFC 9001 keys
 *         derived from the cleartext DCID) for routing/resolution.
 *   - Migration / NAT rebind survival: a short-header datagram from an
 *     unknown source is looked up in the DCID index; on hit the session
 *     is rebound to the new address and (optionally) replies are sprayed
 *     to both old and new address for a short window. On miss a
 *     configurable policy applies (drop, or rebind most-recent session).
 *
 *   NOTE: session state is per-worker. Correct migration handling requires
 *   worker_processes 1 (a warning is logged otherwise). A future version
 *   can move the session table to shared memory.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


#define NGX_QR_CID_MAX          20    /* QUIC v1 max CID length */
#define NGX_QR_IV_LEN           12
#define NGX_QR_TAG_LEN          16
#define NGX_QR_KEY_LEN          16
#define NGX_QR_HP_LEN           5     /* RFC 9001, 5.4.1: 5-byte mask */
#define NGX_QR_SALT_LEN         20
#define NGX_QR_DFLT_BUF         65536
#define NGX_QR_MAX_EARLY        32    /* packets buffered while resolving */
#define NGX_QR_MAX_DCIDS        4     /* server CIDs registered per session */
#define NGX_QR_SWEEP_INTERVAL   10000 /* ms */
#define NGX_QR_STATS_INTERVAL   60000 /* ms */
#define NGX_QR_MAX_PKT          65535
#define NGX_QR_UPSTREAM_PORT     443   /* real QUIC destination port */
#define NGX_QR_MAX_UP_ADDRS      8     /* resolver candidates per route */
#define NGX_QR_CRYPTO_BUF        4096  /* ClientHello reassembly buffer */
#define NGX_QR_PLAIN_BUF         2048  /* decrypted Initial payload */
#define NGX_QR_MAX_HOLES         8     /* out-of-order CRYPTO chunks stashed */
#define NGX_QR_HOLE_MAX          256   /* max stashed CRYPTO chunk (bytes) */
#define NGX_QR_AD_MAX            512   /* AAD (unprotected header) cap: cached
                                          retry/new tokens reach 300+ bytes */
#define NGX_QR_PENDING_MAX       8     /* Initials to wait for the SNI */

/* QUIC v1 initial salt, RFC 9001 section 5.2 */
static const u_char  ngx_qr_initial_salt[NGX_QR_SALT_LEN] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};


typedef struct {
    ngx_flag_t          enable;          /* quic_relay on|off */
    ngx_msec_t          timeout;         /* idle timeout */
    ngx_msec_t          spray_time;      /* dual-send window after rebind */
    ngx_uint_t          max_sessions;
    ngx_flag_t          strict_miss;     /* on: drop unknown-DCID packets */
    ngx_str_t           fallback;        /* host:port used when no SNI */
    ngx_flag_t          sni;             /* decrypt Initial for SNI */

    /* parsed at init: */
    struct sockaddr    *fallback_addr;
    socklen_t           fallback_socklen;

    /* runtime ctx (per cycle) */
    void               *ctx;
} ngx_qr_srv_conf_t;


typedef struct ngx_qr_session_s  ngx_qr_session_t;


typedef struct {
    ngx_rbtree_node_t   node;            /* key: crc32(cid) */
    u_char              cid[NGX_QR_CID_MAX];
    uint8_t             cid_len;
    ngx_qr_session_t   *session;
} ngx_qr_dcid_t;


typedef struct {
    u_char             *data;
    uint16_t            len;
} ngx_qr_early_t;


typedef struct {
    uint32_t            version;
    uint64_t            pn;
    uint64_t            token_len;
    uint64_t            payload_len;
    size_t              ad_len;
} ngx_qr_diag_t;


typedef struct ngx_qr_ctx_s  ngx_qr_ctx_t;


static ngx_uint_t  ngx_qr_session_serial;


struct ngx_qr_session_s {
    ngx_qr_srv_conf_t          *conf;
    ngx_qr_ctx_t               *ctx;
    ngx_pool_t                 *pool;

    /* client side (shared udp connection owned by core recvmsg dispatcher) */
    ngx_connection_t           *client_conn;
    ngx_sockaddr_t              client_sa;
    struct sockaddr            *client_addr;      /* -> client_sa */
    socklen_t                   client_socklen;
    ngx_sockaddr_t              old_sa;
    struct sockaddr            *old_client_addr;  /* -> old_sa, spray target */
    socklen_t                   old_client_socklen;
    ngx_msec_t                  spray_until;

    /* upstream side */
    ngx_socket_t                upstream_fd;
    ngx_connection_t           *upstream_conn;
    ngx_sockaddr_t              up_sa;
    struct sockaddr            *upstream_addr;    /* -> up_sa */
    socklen_t                   upstream_socklen;
    ngx_sockaddr_t              up_list[NGX_QR_MAX_UP_ADDRS];
    socklen_t                   up_socklens[NGX_QR_MAX_UP_ADDRS];
    uint8_t                     n_up;
    uint8_t                     up_idx;
    ngx_resolver_ctx_t         *rctx;
    unsigned                    resolving:1;

    /* learned QUIC parameters */
    u_char                      client_dcid[NGX_QR_CID_MAX]; /* client's SCID
                                                              (= server->client
                                                              DCID) */
    uint8_t                     client_dcid_len;
    uint8_t                     server_scid_len;  /* client->server short hdr
                                                    DCID length */
    u_char                      initial_dcid[NGX_QR_CID_MAX]; /* DCID of the
                                                   client Initial that made
                                                   this session */
    uint8_t                     initial_dcid_len;

    ngx_qr_dcid_t              *dcids[NGX_QR_MAX_DCIDS];
    uint8_t                     n_dcids;

    /* SNI routing */
    ngx_str_t                   sni;
    unsigned                    sni_ok:1;
    unsigned                    retry_seen:1;
    unsigned                    vn_seen:1;
    unsigned                    destroy_pending:1;

    /* ClientHello acquisition while no route yet (the CH may span
     * several Initial packets: e.g. post-quantum key shares) */
    u_char                     *crypto;         /* -> NGX_QR_CRYPTO_BUF */
    size_t                      crypto_len;
    u_char                     *plainbuf;       /* -> NGX_QR_PLAIN_BUF */
    uint8_t                     initials_seen;  /* Initials parsed while
                                                   unrouted */

    /* out-of-order CRYPTO stash: chunks that arrived before their
     * predecessor (multi-Initial ClientHello, reordering) */
    u_char                     *hole_buf;       /* MAX_HOLES * HOLE_MAX */
    uint64_t                    hole_off[NGX_QR_MAX_HOLES];
    size_t                      hole_len[NGX_QR_MAX_HOLES];
    uint8_t                     decrypt_fail_logged;

    /* early packets buffered while resolving */
    ngx_qr_early_t             *early[NGX_QR_MAX_EARLY];
    uint8_t                     n_early;

    /* lifecycle */
    ngx_msec_t                  created;
    ngx_msec_t                  last_activity;
    ngx_queue_t                  queue;

    /* stats */
    uint64_t                    pkts_up, pkts_down;
    uint64_t                    bytes_up, bytes_down;
    uint64_t                    miss_pkts;
    ngx_msec_t                  last_big_down;   /* last downstream packet
                                                   >= 200B (real data,
                                                   not a stateless reset) */
    ngx_msec_t                  last_client_pkt; /* last packet from the
                                                   CURRENT client address */
    uint8_t                     resolve_fails;
    ngx_uint_t                  id;              /* diagnostic serial */
};


typedef struct ngx_qr_ctx_s {
    ngx_rbtree_t                dcid_tree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 sessions;
    ngx_uint_t                  n_sessions;
    ngx_qr_srv_conf_t          *conf;
    ngx_resolver_t             *resolver;
    ngx_log_t                  *log;
    uint32_t                    cid_len_mask;   /* bit l: dcid of length l
                                                   registered */

    /* per-listen socket registry (built in init_module) */
    ngx_array_t                 listens;  /* ngx_listening_t* */

    /* timers */
    ngx_event_t                 sweep_ev;
    ngx_event_t                 stats_ev;

    /* counters */
    uint64_t                    initial_seen;
    uint64_t                    retry_seen;
    uint64_t                    vn_seen;
    uint64_t                    sessions_created;
    uint64_t                    sessions_closed;
    uint64_t                    sessions_evicted;
    uint64_t                    pkts_up, pkts_down;
    uint64_t                    bytes_up, bytes_down;
    uint64_t                    miss_rebound;
    uint64_t                    miss_dropped;
    uint64_t                    miss_unknown;
    uint64_t                    rebinding;
    uint64_t                    parse_err;
    uint64_t                    decrypt_fail;
    uint64_t                    frame_err;
    uint64_t                    sni_ok;
    uint64_t                    sni_fail;
    ngx_msec_t                  last_stats;
} ngx_qr_ctx_t;




static void *ngx_qr_create_srv_conf(ngx_conf_t *cf);
static char *ngx_qr_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_qr_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_qr_init_process(ngx_cycle_t *cycle);
static void ngx_qr_exit_process(ngx_cycle_t *cycle);

static char *ngx_qr_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_qr_ctx_t *ngx_qr_ctx_from_conn(ngx_connection_t *c);

static void ngx_qr_new_peer(ngx_connection_t *c);
static void ngx_qr_packet_handler(ngx_event_t *ev);
static void ngx_qr_process_client_packet(ngx_connection_t *c,
    u_char *data, size_t len);
static ngx_qr_session_t *ngx_qr_create_session(ngx_connection_t *c,
    u_char *data, size_t len);
static void ngx_qr_destroy_session(ngx_qr_session_t *s,
    const char *reason);
static void ngx_qr_rebind_session(ngx_qr_session_t *s, ngx_connection_t *c);
static void ngx_qr_close_udp_conn(ngx_connection_t *c);

static void ngx_qr_resolve_handler(ngx_resolver_ctx_t *rctx);
static ngx_int_t ngx_qr_open_upstream(ngx_qr_session_t *s,
    struct sockaddr *addr, socklen_t socklen);
static ngx_int_t ngx_qr_connect_upstream(ngx_qr_session_t *s);
static void ngx_qr_upstream_addrs(ngx_qr_session_t *s,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs);
static void ngx_qr_route_failed(ngx_qr_session_t *s, const char *reason);
static void ngx_qr_upstream_read(ngx_event_t *ev);
static void ngx_qr_forward(ngx_qr_session_t *s, u_char *data, size_t len);
static void ngx_qr_noop(ngx_event_t *ev);

static void ngx_qr_sweep(ngx_event_t *ev);
static void ngx_qr_stats(ngx_event_t *ev);

/* QUIC parsing helpers */
static ngx_int_t ngx_qr_parse_long_header(u_char *data, size_t len,
    u_char *dcid, uint8_t *dcid_len, u_char *scid, uint8_t *scid_len,
    uint8_t *type);
static ngx_qr_session_t *ngx_qr_lookup_dcid(ngx_qr_ctx_t *ctx,
    u_char *cid, uint8_t cid_len);
static void ngx_qr_register_dcid(ngx_qr_ctx_t *ctx, ngx_qr_session_t *s,
    u_char *cid, uint8_t cid_len);

/* Initial crypto / SNI extraction */
static ngx_int_t ngx_qr_decrypt_initial(u_char *dcid, uint8_t dcid_len,
    u_char *pkt, size_t pkt_len, u_char *plain, size_t plain_size,
    size_t *plain_len, ngx_qr_diag_t *diag, ngx_log_t *log);
static ngx_int_t ngx_qr_extract_sni(u_char *plain, size_t len,
    ngx_str_t *sni, ngx_log_t *log);
static ngx_int_t ngx_qr_varint(u_char **p, u_char *end, uint64_t *value);

static void ngx_qr_try_route(ngx_qr_session_t *s, u_char *data, size_t len,
    u_char *dcid, uint8_t dcid_len);
static ngx_int_t ngx_qr_collect_crypto(ngx_qr_session_t *s, u_char *plain,
    size_t plain_len);
static ngx_int_t ngx_qr_crypto_append(ngx_qr_session_t *s, u_char *data,
    uint64_t flen, uint64_t foff);
static void ngx_qr_crypto_stash(ngx_qr_session_t *s, u_char *data,
    size_t flen, uint64_t foff);
static ngx_command_t  ngx_qr_commands[] = {

    { ngx_string("quic_relay"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, enable),
      NULL },

    { ngx_string("quic_relay_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, timeout),
      NULL },

    { ngx_string("quic_relay_spray"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, spray_time),
      NULL },

    { ngx_string("quic_relay_max_sessions"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, max_sessions),
      NULL },

    { ngx_string("quic_relay_strict_miss"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, strict_miss),
      NULL },

    { ngx_string("quic_relay_sni"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_qr_srv_conf_t, sni),
      NULL },

    { ngx_string("quic_relay_fallback"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_qr_fallback,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_qr_module_ctx = {
    NULL,                     /* preconfiguration */
    NULL,                     /* postconfiguration */

    NULL,                     /* create main configuration */
    NULL,                     /* init main configuration */

    ngx_qr_create_srv_conf,  /* create server configuration */
    ngx_qr_merge_srv_conf    /* merge server configuration */
};


ngx_module_t  ngx_stream_quic_relay_module = {
    NGX_MODULE_V1,
    &ngx_qr_module_ctx,               /* module context */
    ngx_qr_commands,                  /* module directives */
    NGX_STREAM_MODULE,                /* module type */
    NULL,                             /* init master */
    ngx_qr_init_module,               /* init module */
    ngx_qr_init_process,              /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    ngx_qr_exit_process,              /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_qr_create_srv_conf(ngx_conf_t *cf)
{
    ngx_qr_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_qr_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->spray_time = NGX_CONF_UNSET_MSEC;
    conf->max_sessions = NGX_CONF_UNSET_UINT;
    conf->strict_miss = NGX_CONF_UNSET;
    conf->sni = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_qr_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_qr_srv_conf_t  *prev = parent;
    ngx_qr_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 90000);
    ngx_conf_merge_msec_value(conf->spray_time, prev->spray_time, 3000);
    ngx_conf_merge_uint_value(conf->max_sessions, prev->max_sessions, 256);
    ngx_conf_merge_value(conf->strict_miss, prev->strict_miss, 0);
    ngx_conf_merge_value(conf->sni, prev->sni, 1);
    ngx_conf_merge_str_value(conf->fallback, prev->fallback, "");

    if (conf->enable) {
        if (conf->timeout < 5000) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "quic_relay_timeout must be >= 5s");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_qr_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_qr_srv_conf_t  *scf = conf;

    ngx_str_t   *value;
    ngx_url_t    u;

    if (scf->fallback.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 443;
    u.uri_part = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in quic_relay_fallback \"%V\"",
                               u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }

    scf->fallback_addr = u.addrs[0].sockaddr;
    scf->fallback_socklen = u.addrs[0].socklen;
    scf->fallback = value[1];

    return NGX_CONF_OK;
}


static void
ngx_qr_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_qr_dcid_t      *n, *t;
    ngx_rbtree_node_t **p;
    ngx_int_t           rc;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {

            n = (ngx_qr_dcid_t *) node;
            t = (ngx_qr_dcid_t *) temp;

            rc = ngx_memn2cmp(n->cid, t->cid, n->cid_len, t->cid_len);

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_qr_session_t *
ngx_qr_lookup_dcid(ngx_qr_ctx_t *ctx, u_char *cid, uint8_t cid_len)
{
    uint32_t            hash;
    ngx_int_t           rc;
    ngx_qr_dcid_t      *n;
    ngx_rbtree_node_t  *node, *sentinel;

    if (cid_len == 0 || cid_len > NGX_QR_CID_MAX) {
        return NULL;
    }

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, cid, cid_len);
    ngx_crc32_final(hash);

    node = ctx->dcid_tree.root;
    sentinel = ctx->dcid_tree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        n = (ngx_qr_dcid_t *) node;

        rc = ngx_memn2cmp(cid, n->cid, cid_len, n->cid_len);

        if (rc == 0) {
            return n->session;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_qr_register_dcid(ngx_qr_ctx_t *ctx, ngx_qr_session_t *s,
    u_char *cid, uint8_t cid_len)
{
    uint8_t             i;
    uint32_t            hash;
    ngx_qr_dcid_t      *d;

    if (cid_len == 0 || cid_len > NGX_QR_CID_MAX) {
        return;
    }

    if (s->n_dcids >= NGX_QR_MAX_DCIDS) {
        return;
    }

    for (i = 0; i < s->n_dcids; i++) {
        if (s->dcids[i]->cid_len == cid_len
            && ngx_memcmp(s->dcids[i]->cid, cid, cid_len) == 0)
        {
            return;   /* already registered */
        }
    }

    d = ngx_pcalloc(s->pool, sizeof(ngx_qr_dcid_t));
    if (d == NULL) {
        return;
    }

    ngx_memcpy(d->cid, cid, cid_len);
    d->cid_len = cid_len;
    d->session = s;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, cid, cid_len);
    ngx_crc32_final(hash);

    d->node.key = hash;

    ngx_rbtree_insert(&ctx->dcid_tree, &d->node);

    s->dcids[s->n_dcids++] = d;

    ctx->cid_len_mask |= 1u << cid_len;
}

/* ---------------------------------------------------------------------- */
/* module init: patch ls->handler for udp listen sockets of enabled servers */

static ngx_array_t *ngx_qr_ctxs = NULL;   /* ngx_qr_ctx_t* registry */
static const char *ngx_qr_fail = "none";  /* last crypto failure point */


static ngx_qr_srv_conf_t *
ngx_qr_srv_conf_of_listening(ngx_listening_t *ls)
{
    ngx_stream_port_t          *stport;
    ngx_stream_core_srv_conf_t *cscf;
    ngx_stream_conf_ctx_t      *conf_ctx;

    stport = ls->servers;
    if (stport == NULL || stport->naddrs == 0) {
        return NULL;
    }

    switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        cscf = ((ngx_stream_in6_addr_t *) stport->addrs)[0].conf.default_server;
        break;
#endif

    default: /* AF_INET */
        cscf = ((ngx_stream_in_addr_t *) stport->addrs)[0].conf.default_server;
        break;
    }

    if (cscf == NULL || cscf->ctx == NULL) {
        return NULL;
    }

    conf_ctx = cscf->ctx;

    return conf_ctx->srv_conf[ngx_stream_quic_relay_module.ctx_index];
}


static ngx_int_t
ngx_qr_init_module(ngx_cycle_t *cycle)
{
    ngx_uint_t           i, k;
    ngx_listening_t     *ls;
    ngx_qr_srv_conf_t   *scf;
    ngx_qr_ctx_t        *ctx;
    ngx_core_conf_t     *ccf;
    ngx_stream_core_srv_conf_t *cscf;
    ngx_listening_t    **lsp;

    /* one fresh registry per cycle */
    ngx_qr_ctxs = ngx_array_create(cycle->pool, 4, sizeof(ngx_qr_ctx_t *));
    if (ngx_qr_ctxs == NULL) {
        return NGX_ERROR;
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {

        if (ls[i].type != SOCK_DGRAM) {
            continue;
        }

        if (ls[i].handler != ngx_stream_init_connection) {
            /* not a stream-managed listen socket */
            continue;
        }

        scf = ngx_qr_srv_conf_of_listening(&ls[i]);
        if (scf == NULL || !scf->enable) {
            continue;
        }

        if (scf->ctx == NULL) {
            ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_qr_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }

            ngx_rbtree_init(&ctx->dcid_tree, &ctx->sentinel,
                            ngx_qr_rbtree_insert);
            ngx_queue_init(&ctx->sessions);

            if (ngx_array_init(&ctx->listens, cycle->pool, 4,
                               sizeof(ngx_listening_t *)) != NGX_OK)
            {
                return NGX_ERROR;
            }

            ctx->conf = scf;
            ctx->log = cycle->log;

            /* resolver from the stream core server conf of the default
             * server on this port (the fork's resolver: interface=,
             * prefer_ipv6= aware) */
            cscf = NULL;
            switch (ls[i].sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                cscf = ((ngx_stream_in6_addr_t *)
                        ((ngx_stream_port_t *) ls[i].servers)->addrs)[0]
                       .conf.default_server;
                break;
#endif
            default:
                cscf = ((ngx_stream_in_addr_t *)
                        ((ngx_stream_port_t *) ls[i].servers)->addrs)[0]
                       .conf.default_server;
                break;
            }
            if (cscf != NULL) {
                ctx->resolver = cscf->resolver;
            }

            scf->ctx = ctx;

            {
                ngx_qr_ctx_t **slot = ngx_array_push(ngx_qr_ctxs);
                if (slot == NULL) {
                    return NGX_ERROR;
                }
                *slot = ctx;
            }
        }

        ctx = scf->ctx;

        lsp = ngx_array_push(&ctx->listens);
        if (lsp == NULL) {
            return NGX_ERROR;
        }
        *lsp = &ls[i];

        ls[i].handler = ngx_qr_new_peer;

        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                      "quic_relay: took over udp listen %V",
                      &ls[i].addr_text);
    }

    /* sanity: session state is per-worker */
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    for (k = 0; ngx_qr_ctxs != NULL && k < ngx_qr_ctxs->nelts; k++) {
        ctx = ((ngx_qr_ctx_t **) ngx_qr_ctxs->elts)[k];

        if (ctx->resolver == NULL) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "quic_relay: no \"resolver\" configured for the"
                          " quic_relay server; only quic_relay_fallback"
                          " routing will work");
        }

        if (ccf->worker_processes != 1) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "quic_relay: worker_processes is %ui;"
                          " migration handling requires worker_processes 1",
                          ccf->worker_processes);
        }
    }

    return NGX_OK;
}


static ngx_qr_ctx_t *
ngx_qr_ctx_from_conn(ngx_connection_t *c)
{
    ngx_uint_t       i, j;
    ngx_qr_ctx_t   **ctxp;

    if (ngx_qr_ctxs == NULL) {
        return NULL;
    }

    ctxp = ngx_qr_ctxs->elts;

    for (i = 0; i < ngx_qr_ctxs->nelts; i++) {

        ngx_listening_t  **lsp = ctxp[i]->listens.elts;

        for (j = 0; j < ctxp[i]->listens.nelts; j++) {
            if (lsp[j] == c->listening) {
                return ctxp[i];
            }
        }
    }

    return NULL;
}


/* ---------------------------------------------------------------------- */
/* client-side entry points */

static void
ngx_qr_new_peer(ngx_connection_t *c)
{
    ngx_qr_ctx_t  *ctx;

    ctx = ngx_qr_ctx_from_conn(c);
    if (ctx == NULL) {
        /* not ours (should not happen) */
        ngx_qr_close_udp_conn(c);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "quic_relay: new peer (len %z, port %d)",
                  c->buffer ? (size_t) (c->buffer->last - c->buffer->pos) : 0,
                  (int) ngx_inet_get_port(c->sockaddr));

    c->data = NULL;
    c->read->handler = ngx_qr_packet_handler;

    if (c->buffer == NULL) {
        return;
    }

    ngx_qr_process_client_packet(c, c->buffer->pos,
                                 c->buffer->last - c->buffer->pos);
}


static void
ngx_qr_packet_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ev->data;

    if (c->udp == NULL) {
        return;
    }

    b = c->udp->buffer;

    if (b == NULL || b->last - b->pos == 0) {
        return;
    }

    ngx_qr_process_client_packet(c, b->pos, b->last - b->pos);
}


static void
ngx_qr_process_client_packet(ngx_connection_t *c, u_char *data, size_t len)
{
    u_char             b0, dcid[NGX_QR_CID_MAX], scid[NGX_QR_CID_MAX];
    uint8_t            dcid_len, scid_len, type, l;
    uint32_t           version;
    ngx_int_t          same;
    ngx_qr_ctx_t      *ctx;
    ngx_qr_session_t  *s, *s2;

    s = c->data;
    ctx = (s != NULL) ? s->ctx : ngx_qr_ctx_from_conn(c);

    if (ctx == NULL) {
        return;
    }

    if (len < 6) {
        ctx->parse_err++;
        return;
    }

    b0 = data[0];

    if (b0 & 0x80) {

        /* long header: self-describing */

        if (ngx_qr_parse_long_header(data, len, dcid, &dcid_len, scid,
                                     &scid_len, &type) != NGX_OK)
        {
            ctx->parse_err++;
            return;
        }

        version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

        if (version == 0) {
            /* Version Negotiation from a client: not expected */
            ctx->vn_seen++;
            return;
        }

        if (type == 0) {

            /* Initial: session (re)birth — or a continuation of the live
             * session after Retry (the new DCID equals the Retry SCID,
             * which was registered in the DCID index when the Retry
             * passed through), or a re-used server CID (same upstream).
             * Both must keep the SAME upstream socket: the server bound
             * its Retry token / connection state to it. */

            ctx->initial_seen++;

            s2 = (dcid_len > 0) ? ngx_qr_lookup_dcid(ctx, dcid, dcid_len)
                                : NULL;

            same = (s != NULL
                    && s->initial_dcid_len == dcid_len
                    && ngx_memcmp(s->initial_dcid, dcid, dcid_len) == 0);

            if (s != NULL && !same && s2 == s) {
                same = 1;           /* post-Retry re-Initial */
            }

            if (s == NULL && s2 != NULL) {
                /* re-Initial after a rebind: DCID still known */
                ctx->rebinding++;
                ngx_qr_rebind_session(s2, c);
                s = s2;
                same = 1;
            }

            if (!same) {
                if (s != NULL) {
                    ngx_qr_destroy_session(s, "replaced by new Initial");
                    /* the udp conn stays alive: the new session below
                     * re-attaches to it */
                }

                s = ngx_qr_create_session(c, data, len);
                if (s == NULL) {
                    return;
                }
            }

            /* route acquisition while unrouted: the ClientHello may
             * span several Initial packets */

            if (s->upstream_fd == -1 && !s->resolving && !s->sni_ok) {
                ngx_qr_try_route(s, data, len, dcid, dcid_len);
            }

            ngx_qr_forward(s, data, len);
            return;
        }

        /* 0-RTT / Handshake */

        if (s != NULL) {
            ngx_qr_forward(s, data, len);
            return;
        }

        s2 = ngx_qr_lookup_dcid(ctx, dcid, dcid_len);
        if (s2 != NULL) {
            ctx->rebinding++;
            ngx_qr_rebind_session(s2, c);
            ngx_qr_forward(s2, data, len);
            return;
        }

        goto miss;

    } else {

        /* short header (1-RTT): fast path when the source address is known */

        if (s != NULL) {
            ngx_qr_forward(s, data, len);
            return;
        }

        /* unknown source address: try the DCID index at every CID length
         * we have ever registered */

        for (l = 1; l <= NGX_QR_CID_MAX; l++) {

            if (!(ctx->cid_len_mask & (1u << l))) {
                continue;
            }

            if (1 + (size_t) l > len) {
                continue;
            }

            s2 = ngx_qr_lookup_dcid(ctx, &data[1], l);
            if (s2 != NULL) {
                ctx->rebinding++;
                ngx_qr_rebind_session(s2, c);
                ngx_qr_forward(s2, data, len);
                return;
            }
        }

        goto miss;
    }

miss:

    ctx->miss_unknown++;

    if (ctx->conf->strict_miss) {
        ctx->miss_dropped++;
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "quic_relay: dropped unknown-source packet"
                       " (%uz bytes)", len);
        return;
    }

    /* Last resort: the miss carries a CID issued in encrypted
     * NEW_CONNECTION_ID frames, invisible to the relay, so the target
     * session must be inferred.  Heuristic: the most recently active
     * session -- a migrating client keeps its old path busy right up to
     * the switch (Cronet path probing), making its own session the
     * busiest at the moment of the miss.  This is exact for the
     * sequential single-client case (the phone); simultaneous
     * migrations of two clients within the same instant remain a known
     * limitation (documented in QUIC-RELAY.md). */

    s2 = NULL;
    {
        ngx_queue_t      *q;
        ngx_qr_session_t *cand;
        ngx_msec_t        best = 0;

        for (q = ngx_queue_head(&ctx->sessions);
             q != ngx_queue_sentinel(&ctx->sessions);
             q = ngx_queue_next(q))
        {
            cand = ngx_queue_data(q, ngx_qr_session_t, queue);
            if (cand->last_activity >= best) {
                best = cand->last_activity;
                s2 = cand;
            }
        }
    }

    if (s2 != NULL) {
        s2->miss_pkts++;
        ctx->miss_rebound++;
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                      "quic_relay: miss rebound to most-recent session"
                      " #%ui (dcid unknown, %uz bytes, port %d)",
                      s2->id, len, (int) ngx_inet_get_port(c->sockaddr));
        ngx_qr_rebind_session(s2, c);
        ngx_qr_forward(s2, data, len);
        return;
    }

    ctx->miss_dropped++;
}


/* ---------------------------------------------------------------------- */
/* session lifecycle */

static ngx_qr_session_t *
ngx_qr_create_session(ngx_connection_t *c, u_char *data, size_t len)
{
    ngx_qr_ctx_t            *ctx;
    ngx_qr_srv_conf_t       *conf;
    ngx_qr_session_t        *s;
    ngx_pool_t              *pool;
    u_char                   dcid[NGX_QR_CID_MAX], scid[NGX_QR_CID_MAX];
    uint8_t                  dcid_len, scid_len, type;

    ctx = ngx_qr_ctx_from_conn(c);
    if (ctx == NULL) {
        return NULL;
    }

    conf = ctx->conf;

    if (ctx->n_sessions >= conf->max_sessions) {
        /* evict the most idle session */
        ngx_queue_t      *q;
        ngx_qr_session_t *victim = NULL;
        ngx_msec_t        oldest = NGX_MAX_INT_T_VALUE;

        for (q = ngx_queue_head(&ctx->sessions);
             q != ngx_queue_sentinel(&ctx->sessions);
             q = ngx_queue_next(q))
        {
            ngx_qr_session_t *cand;
            cand = ngx_queue_data(q, ngx_qr_session_t, queue);
            if (cand->last_activity < oldest) {
                oldest = cand->last_activity;
                victim = cand;
            }
        }

        if (victim != NULL) {
            ngx_connection_t *vc = victim->client_conn;
            ngx_qr_destroy_session(victim, "evicted");
            if (vc != NULL && vc != c) {
                ngx_qr_close_udp_conn(vc);
            }
            ctx->sessions_evicted++;
        }
    }

    pool = ngx_create_pool(4096, ctx->log);
    if (pool == NULL) {
        return NULL;
    }

    s = ngx_pcalloc(pool, sizeof(ngx_qr_session_t));
    if (s == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    s->pool = pool;
    s->conf = conf;
    s->ctx = ctx;

    s->client_conn = c;
    s->client_addr = (struct sockaddr *) &s->client_sa;
    ngx_memcpy(s->client_addr, c->sockaddr, c->socklen);
    s->client_socklen = c->socklen;

    s->upstream_fd = -1;

    if (ngx_qr_parse_long_header(data, len, dcid, &dcid_len, scid,
                                 &scid_len, &type) == NGX_OK)
    {
        ngx_memcpy(s->initial_dcid, dcid, dcid_len);
        s->initial_dcid_len = dcid_len;
        ngx_memcpy(s->client_dcid, scid, scid_len);
        s->client_dcid_len = scid_len;
    }

    s->created = s->last_activity = ngx_current_msec;
    s->last_client_pkt = ngx_current_msec;
    s->id = ++ngx_qr_session_serial;

    c->data = s;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "quic_relay: session #%ui created, dcid_len=%ui"
                  " scid_len=%ui",
                  s->id, (ngx_uint_t) dcid_len, (ngx_uint_t) scid_len);

    ngx_queue_insert_tail(&ctx->sessions, &s->queue);
    ctx->n_sessions++;
    ctx->sessions_created++;

    /* Routing (SNI via possibly multi-Initial ClientHello reassembly,
     * or the fallback address) is driven by ngx_qr_try_route() from the
     * packet path: the session may stay "pending" (no upstream yet)
     * across several Initial packets until the ClientHello is complete.
     * Unrouted sessions are reaped by the idle sweep / eviction. */

    return s;
}


static void
ngx_qr_destroy_session(ngx_qr_session_t *s, const char *reason)
{
    uint8_t         i;
    ngx_qr_ctx_t   *ctx = s->ctx;

    if (s->destroy_pending) {
        return;
    }
    s->destroy_pending = 1;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "quic_relay: session done: sni=%V life=%uis "
                  "up=%uLpkts/%uLB down=%uLpkts/%uLB miss=%uL retry=%ui"
                  " reason=%s",
                  &s->sni,
                  (ngx_uint_t) ((ngx_current_msec - s->created) / 1000),
                  s->pkts_up, s->bytes_up, s->pkts_down, s->bytes_down,
                  s->miss_pkts, s->retry_seen, reason);

    /* pending async resolution */
    if (s->resolving && s->rctx != NULL) {
        s->rctx->data = NULL;             /* handler will see NULL */
        ngx_resolve_name_done(s->rctx);
        s->rctx = NULL;
        s->resolving = 0;
    }

    /* detach from client conn */
    if (s->client_conn != NULL && s->client_conn->data == s) {
        s->client_conn->data = NULL;
    }
    s->client_conn = NULL;

    /* close upstream */
    if (s->upstream_conn != NULL) {
        ngx_close_connection(s->upstream_conn);
        s->upstream_conn = NULL;
        s->upstream_fd = -1;
    } else if (s->upstream_fd != -1) {
        ngx_close_socket(s->upstream_fd);
        s->upstream_fd = -1;
    }

    /* unregister dcids */
    for (i = 0; i < s->n_dcids; i++) {
        ngx_rbtree_delete(&ctx->dcid_tree, &s->dcids[i]->node);
    }


    /* early buffers freed with the pool */

    ngx_queue_remove(&s->queue);
    ctx->n_sessions--;
    ctx->sessions_closed++;
    ctx->pkts_up += s->pkts_up;
    ctx->pkts_down += s->pkts_down;
    ctx->bytes_up += s->bytes_up;
    ctx->bytes_down += s->bytes_down;

    ngx_destroy_pool(s->pool);
}


static void
ngx_qr_rebind_session(ngx_qr_session_t *s, ngx_connection_t *c)
{
    ngx_connection_t  *old;

    if (s->client_conn == c) {
        return;
    }

    old = s->client_conn;

    if (old != NULL) {
        if (old->data == s) {
            old->data = NULL;
        }
        /* remember the old address for spraying replies */
        if (s->conf->spray_time) {
            ngx_memcpy(&s->old_sa, old->sockaddr, old->socklen);
            s->old_client_addr = (struct sockaddr *) &s->old_sa;
            s->old_client_socklen = old->socklen;
            s->spray_until = ngx_current_msec + s->conf->spray_time;
        }
        ngx_qr_close_udp_conn(old);
    }

    ngx_memcpy(&s->client_sa, c->sockaddr, c->socklen);
    s->client_addr = (struct sockaddr *) &s->client_sa;
    s->client_socklen = c->socklen;
    s->client_conn = c;
    c->data = s;

    ngx_log_error(NGX_LOG_INFO, s->ctx->log, 0,
                  "quic_relay: session #%ui rebound to new client address"
                  " (port %d)",
                  s->id, (int) ngx_inet_get_port(c->sockaddr));
}


static void
ngx_qr_close_udp_conn(ngx_connection_t *c)
{
    /* replicates ngx_close_accepted_udp_connection() from
     * src/event/ngx_event_udp.c — safe for shared udp connections
     * (does not close the shared listen fd) */

    if (c == NULL) {
        return;
    }

    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }
}


/* ---------------------------------------------------------------------- */
/* resolver + upstream */

static void
ngx_qr_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_qr_session_t   *s = rctx->data;

    if (s == NULL) {
        /* session destroyed while resolving */
        ngx_resolve_name_done(rctx);
        return;
    }

    s->resolving = 0;
    s->rctx = NULL;

    if (rctx->state || rctx->naddrs == 0) {
        ngx_log_error(NGX_LOG_WARN, s->ctx->log, 0,
                      "quic_relay: resolve \"%V\" failed (%i)",
                      &rctx->name, rctx->state);

        ngx_resolve_name_done(rctx);
        ngx_qr_route_failed(s, "resolve-failed");
        return;
    }

    /* NOTE: ctx->addr is only populated for single-address answers;
     * the general API is ctx->addrs[0..naddrs) (see ngx_resolver.c) */

    ngx_qr_upstream_addrs(s, rctx->addrs, rctx->naddrs);

    ngx_resolve_name_done(rctx);

    if (ngx_qr_connect_upstream(s) != NGX_OK) {
        ngx_qr_route_failed(s, "no reachable upstream address");
    }
}


static void
ngx_qr_route_failed(ngx_qr_session_t *s, const char *reason)
{
    ngx_connection_t  *cc;

    s->resolve_fails++;

    if (s->conf->fallback_addr != NULL) {
        ngx_qr_open_upstream(s, s->conf->fallback_addr,
                             s->conf->fallback_socklen);
        return;
    }

    cc = s->client_conn;
    ngx_qr_destroy_session(s, reason);
    if (cc != NULL) {
        ngx_qr_close_udp_conn(cc);
    }
}


static void
ngx_qr_upstream_addrs(ngx_qr_session_t *s, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs)
{
    ngx_uint_t  i, n = 0;

    /* prefer IPv4 (the relay host may have no IPv6 egress); keep the
     * resolver order within each family. Ports are set to the real QUIC
     * service port (DNS answers carry no port). */

    for (i = 0; i < naddrs && n < NGX_QR_MAX_UP_ADDRS; i++) {
        if (addrs[i].sockaddr->sa_family == AF_INET) {
            ngx_memcpy(&s->up_list[n], addrs[i].sockaddr, addrs[i].socklen);
            s->up_socklens[n] = addrs[i].socklen;
            n++;
        }
    }

    for (i = 0; i < naddrs && n < NGX_QR_MAX_UP_ADDRS; i++) {
        if (addrs[i].sockaddr->sa_family != AF_INET) {
            ngx_memcpy(&s->up_list[n], addrs[i].sockaddr, addrs[i].socklen);
            s->up_socklens[n] = addrs[i].socklen;
            n++;
        }
    }

    for (i = 0; i < n; i++) {
        if (s->up_list[i].sockaddr.sa_family == AF_INET) {
            s->up_list[i].sockaddr_in.sin_port = htons(NGX_QR_UPSTREAM_PORT);
#if (NGX_HAVE_INET6)
        } else {
            s->up_list[i].sockaddr_in6.sin6_port =
                htons(NGX_QR_UPSTREAM_PORT);
#endif
        }
    }

    s->n_up = (uint8_t) n;
    s->up_idx = 0;
}


static ngx_int_t
ngx_qr_connect_upstream(ngx_qr_session_t *s)
{
    int                 rcvbuf;
    uint8_t             i;
    ngx_socket_t        fd;
    ngx_connection_t   *uc;
    ngx_qr_ctx_t       *ctx = s->ctx;
    struct sockaddr    *addr;

    while (s->up_idx < s->n_up) {

        addr = (struct sockaddr *) &s->up_list[s->up_idx];

        fd = socket(addr->sa_family, SOCK_DGRAM, 0);
        if (fd == -1) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno,
                          "quic_relay: upstream socket() failed");
            s->up_idx++;
            continue;
        }

        if (ngx_nonblocking(fd) == -1) {
            ngx_close_socket(fd);
            s->up_idx++;
            continue;
        }

        rcvbuf = 8 * 1024 * 1024;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        rcvbuf = 8 * 1024 * 1024;
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));

        if (connect(fd, addr, s->up_socklens[s->up_idx]) == -1) {
            u_char     ipbuf[NGX_SOCKADDR_STRLEN];
            ngx_str_t  ip;

            ip.data = ipbuf;
            ip.len = ngx_sock_ntop(addr, s->up_socklens[s->up_idx], ipbuf,
                                   NGX_SOCKADDR_STRLEN, 1);
            ngx_log_error(NGX_LOG_WARN, ctx->log, ngx_socket_errno,
                          "quic_relay: upstream connect() to %V failed,"
                          " trying next address", &ip);
            ngx_close_socket(fd);
            s->up_idx++;
            continue;
        }

        uc = ngx_get_connection(fd, ctx->log);
        if (uc == NULL) {
            ngx_close_socket(fd);
            s->up_idx++;
            continue;
        }

        uc->data = s;
        uc->read->handler = ngx_qr_upstream_read;
        uc->write->handler = ngx_qr_noop;

        if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_free_connection(uc);
            ngx_close_socket(fd);
            s->up_idx++;
            continue;
        }

        s->upstream_conn = uc;
        s->upstream_fd = fd;

        ngx_memcpy(&s->up_sa, addr, s->up_socklens[s->up_idx]);
        s->upstream_addr = (struct sockaddr *) &s->up_sa;
        s->upstream_socklen = s->up_socklens[s->up_idx];

        {
            u_char     ipbuf[NGX_SOCKADDR_STRLEN];
            ngx_str_t  ip;

            ip.data = ipbuf;
            ip.len = ngx_sock_ntop(addr, s->up_socklens[s->up_idx], ipbuf,
                                   NGX_SOCKADDR_STRLEN, 1);
            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                          "quic_relay: upstream fd:%d open for sni=%V -> %V"
                          " (address %ui of %ui)",
                          fd, &s->sni, &ip, (ngx_uint_t) s->up_idx + 1,
                          (ngx_uint_t) s->n_up);
        }

        /* flush early-buffered packets */

        for (i = 0; i < s->n_early; i++) {
            (void) send(fd, s->early[i]->data, s->early[i]->len, 0);
            s->pkts_up++;
            s->bytes_up += s->early[i]->len;
        }
        s->n_early = 0;

        return NGX_OK;
    }

    return NGX_ERROR;   /* all candidate addresses failed */
}


static ngx_int_t
ngx_qr_open_upstream(ngx_qr_session_t *s, struct sockaddr *addr,
    socklen_t socklen)
{
    ngx_memcpy(&s->up_list[0], addr, socklen);
    s->up_socklens[0] = socklen;
    s->n_up = 1;
    s->up_idx = 0;

    return ngx_qr_connect_upstream(s);
}


static void
ngx_qr_upstream_read(ngx_event_t *ev)
{
    u_char              buf[NGX_QR_MAX_PKT];
    ssize_t             n;
    ngx_connection_t   *uc;
    ngx_qr_session_t   *s;
    ngx_qr_ctx_t       *ctx;

    uc = ev->data;
    s = uc->data;

    if (s == NULL) {
        return;
    }

    ctx = s->ctx;

    for ( ;; ) {

        n = recv(uc->fd, buf, sizeof(buf), 0);

        if (n == -1) {
            if (ngx_socket_errno == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno,
                          "quic_relay: upstream recv() failed");
            break;
        }

        if (n == 0) {
            break;
        }

        if (s->pkts_down == 0) {
            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                          "quic_relay: first downstream packet: %uz bytes"
                          " (sni=%V)", (size_t) n, &s->sni);
        }

        if ((size_t) n >= 200) {
            /* big-packet marker: stateless resets from a wrong edge are
             * small; real response traffic is MTU-sized.  Used by the
             * miss-trial confirmation. */
            s->last_big_down = ngx_current_msec;
        }

        ctx->pkts_down++;
        ctx->bytes_down += n;
        s->pkts_down++;
        s->bytes_down += n;
        s->last_activity = ngx_current_msec;

        /* learn + register server CIDs from long headers */

        if (n > 6 && (buf[0] & 0x80)) {
            u_char   dcid[NGX_QR_CID_MAX], scid[NGX_QR_CID_MAX];
            uint8_t  dcid_len, scid_len, type;

            if (ngx_qr_parse_long_header(buf, n, dcid, &dcid_len, scid,
                                         &scid_len, &type) == NGX_OK)
            {
                if (scid_len > 0) {
                    if (s->server_scid_len == 0) {
                        s->server_scid_len = scid_len;
                    }
                    ngx_qr_register_dcid(ctx, s, scid, scid_len);
                }

                if (type == 3) {
                    ctx->retry_seen++;
                    s->retry_seen = 1;
                }
            }

            if (buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[4] == 0) {
                ctx->vn_seen++;
                s->vn_seen = 1;
            }
        }

        /* deliver to the client via the listen socket */

        (void) sendto(s->client_conn->fd, buf, n, 0,
                      s->client_addr, s->client_socklen);

        if (s->spray_until > ngx_current_msec
            && s->old_client_addr != NULL)
        {
            (void) sendto(s->client_conn->fd, buf, n, 0,
                          s->old_client_addr, s->old_client_socklen);
        }
    }
}


static void
ngx_qr_forward(ngx_qr_session_t *s, u_char *data, size_t len)
{
    ngx_qr_ctx_t  *ctx = s->ctx;

    s->last_activity = ngx_current_msec;
    s->last_client_pkt = ngx_current_msec;
    ctx->pkts_up++;
    ctx->bytes_up += len;
    s->pkts_up++;
    s->bytes_up += len;

    if (s->upstream_fd != -1) {
        (void) send(s->upstream_fd, data, len, 0);
        return;
    }

    /* buffer while pending (no route yet) or resolving */

    if (s->upstream_fd == -1 && s->n_early < NGX_QR_MAX_EARLY) {
        ngx_qr_early_t  *e;

        e = ngx_palloc(s->pool, sizeof(ngx_qr_early_t) + len);
        if (e == NULL) {
            return;
        }

        e->data = (u_char *) (e + 1);
        e->len = len;
        ngx_memcpy(e->data, data, len);

        s->early[s->n_early++] = e;
    }
}


/* ---------------------------------------------------------------------- */
/* timers */

static void
ngx_qr_sweep(ngx_event_t *ev)
{
    ngx_queue_t          *q, *next;
    ngx_qr_ctx_t         *ctx = ev->data;
    ngx_qr_session_t     *s;
    ngx_connection_t     *cc;
    ngx_msec_t            now = ngx_current_msec;

    for (q = ngx_queue_head(&ctx->sessions);
         q != ngx_queue_sentinel(&ctx->sessions);
         q = next)
    {
        next = ngx_queue_next(q);

        s = ngx_queue_data(q, ngx_qr_session_t, queue);

        if (now - s->last_activity > s->conf->timeout) {
            cc = s->client_conn;
            ngx_qr_destroy_session(s, "idle");
            if (cc != NULL) {
                ngx_qr_close_udp_conn(cc);
            }
        }
    }

    ngx_add_timer(&ctx->sweep_ev, NGX_QR_SWEEP_INTERVAL);
}


static void
ngx_qr_stats(ngx_event_t *ev)
{
    ngx_qr_ctx_t  *ctx = ev->data;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "quic_relay: stats: sessions=%ui/%ui initial=%uL retry=%uL"
                  " vn=%uL up=%uLpkts/%uLB down=%uLpkts/%uLB"
                  " rebind=%uL missRebound=%uL missDropped=%uL"
                  " missUnknown=%uL sniOk=%uL sniFail=%uL parseErr=%uL"
                  " decryptFail=%uL frameErr=%uL",
                  ctx->n_sessions, ctx->conf->max_sessions,
                  ctx->initial_seen, ctx->retry_seen, ctx->vn_seen,
                  ctx->pkts_up, ctx->bytes_up,
                  ctx->pkts_down, ctx->bytes_down,
                  ctx->rebinding, ctx->miss_rebound, ctx->miss_dropped,
                  ctx->miss_unknown, ctx->sni_ok, ctx->sni_fail,
                  ctx->parse_err, ctx->decrypt_fail, ctx->frame_err);

    ngx_add_timer(&ctx->stats_ev, NGX_QR_STATS_INTERVAL);
}


static ngx_int_t
ngx_qr_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t   i;
    ngx_qr_ctx_t **ctxp;

    if (ngx_qr_ctxs == NULL) {
        return NGX_OK;
    }

    ctxp = ngx_qr_ctxs->elts;

    for (i = 0; i < ngx_qr_ctxs->nelts; i++) {

        ctxp[i]->log = &cycle->new_log;

        ngx_memzero(&ctxp[i]->sweep_ev, sizeof(ngx_event_t));
        ctxp[i]->sweep_ev.log = &cycle->new_log;
        ctxp[i]->sweep_ev.data = ctxp[i];
        ctxp[i]->sweep_ev.handler = ngx_qr_sweep;
        ngx_add_timer(&ctxp[i]->sweep_ev, NGX_QR_SWEEP_INTERVAL);

        ngx_memzero(&ctxp[i]->stats_ev, sizeof(ngx_event_t));
        ctxp[i]->stats_ev.log = &cycle->new_log;
        ctxp[i]->stats_ev.data = ctxp[i];
        ctxp[i]->stats_ev.handler = ngx_qr_stats;
        ngx_add_timer(&ctxp[i]->stats_ev, NGX_QR_STATS_INTERVAL);
    }

    return NGX_OK;
}


static void
ngx_qr_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t   i;
    ngx_qr_ctx_t **ctxp;

    if (ngx_qr_ctxs == NULL) {
        return;
    }

    ctxp = ngx_qr_ctxs->elts;

    for (i = 0; i < ngx_qr_ctxs->nelts; i++) {
        if (ctxp[i]->sweep_ev.timer_set) {
            ngx_del_timer(&ctxp[i]->sweep_ev);
        }
        if (ctxp[i]->stats_ev.timer_set) {
            ngx_del_timer(&ctxp[i]->stats_ev);
        }
    }
}

/* ---------------------------------------------------------------------- */
/* QUIC wire format helpers */

static ngx_int_t
ngx_qr_parse_long_header(u_char *data, size_t len,
    u_char *dcid, uint8_t *dcid_len, u_char *scid, uint8_t *scid_len,
    uint8_t *type)
{
    u_char   *p = data;
    uint8_t   dl, sl;

    *dcid_len = 0;
    *scid_len = 0;
    *type = 0;

    if (len < 7) {
        return NGX_ERROR;
    }

    if (!(data[0] & 0x80)) {
        return NGX_ERROR;
    }

    *type = (data[0] >> 4) & 0x03;    /* RFC 9000 17.2: type = bits 5-4
                                          (bit 6 = fixed bit, see
                                          NGX_QUIC_PKT_HANDSHAKE 0x20) */

    p += 1 + 4;                        /* flags + version */

    dl = *p++;
    if (dl > NGX_QR_CID_MAX) {
        return NGX_ERROR;
    }
    if ((size_t) (p - data) + dl + 1 > len) {
        return NGX_ERROR;
    }
    if (dl > 0) {
        ngx_memcpy(dcid, p, dl);
    }
    *dcid_len = dl;
    p += dl;

    sl = *p++;
    if (sl > NGX_QR_CID_MAX) {
        return NGX_ERROR;
    }
    if ((size_t) (p - data) + sl > len) {
        return NGX_ERROR;
    }
    if (sl > 0) {
        ngx_memcpy(scid, p, sl);
    }
    *scid_len = sl;

    return NGX_OK;
}


static ngx_int_t
ngx_qr_varint(u_char **p, u_char *end, uint64_t *value)
{
    u_char    *b = *p;
    uint8_t   prefix;
    size_t    rest;
    size_t    i;

    if (b >= end) {
        return NGX_ERROR;
    }

    prefix = b[0] >> 6;
    rest = (size_t) 1 << prefix;       /* 1, 2, 4 or 8 bytes */

    if ((size_t) (end - b) < rest) {
        return NGX_ERROR;
    }

    *value = b[0] & 0x3f;

    for (i = 1; i < rest; i++) {
        *value = (*value << 8) | b[i];
    }

    *p = b + rest;

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* Initial packet decryption (RFC 9001): derive client initial keys from the
 * cleartext DCID, remove header protection, AEAD-open the payload.
 * Algorithm mirrors ngx_event_quic_protection.c. */

/* RFC 5869 HKDF implemented with plain HMAC: this OpenSSL build does not
 * support the legacy EVP_PKEY_CTX HKDF ctrl path (-2) and lacks the
 * one-shot HKDF_extract/HKDF_expand header. */

static ngx_int_t ngx_qr_hkdf_expand(u_char *out, size_t out_len,
    const EVP_MD *digest, const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len);

static ngx_int_t
ngx_qr_hkdf_expand_label(u_char *out, size_t out_len,
    const u_char *prk, size_t prk_len, const char *label)
{
    /* TLS 1.3 / RFC 9001 structured label:
     * info = uint16(out_len) || uint8(len("tls13 " + label))
     *        || "tls13 " + label || uint8(0)  */
    u_char   info[32];
    size_t   label_len = ngx_strlen(label);
    size_t   n = 0;

    if (label_len > 16 || out_len > 64) {
        return NGX_ERROR;
    }

    info[n++] = (u_char) (out_len >> 8);
    info[n++] = (u_char) (out_len & 0xff);
    info[n++] = (u_char) (6 + label_len);
    ngx_memcpy(info + n, "tls13 ", 6);
    n += 6;
    ngx_memcpy(info + n, label, label_len);
    n += label_len;
    info[n++] = 0;

    return ngx_qr_hkdf_expand(out, out_len, EVP_sha256(), prk, prk_len,
                              info, n);
}


static ngx_int_t
ngx_qr_hkdf_extract(u_char *out, size_t *out_len, const EVP_MD *digest,
    const u_char *secret, size_t secret_len, const u_char *salt,
    size_t salt_len)
{
    unsigned int  len;

    if (*out_len < 32) {
        return NGX_ERROR;
    }

    if (HMAC(digest, salt, (int) salt_len, secret, secret_len,
             out, &len) == NULL || len != 32)
    {
        return NGX_ERROR;
    }

    *out_len = len;

    return NGX_OK;
}


static ngx_int_t
ngx_qr_hkdf_expand(u_char *out, size_t out_len, const EVP_MD *digest,
    const u_char *prk, size_t prk_len, const u_char *info, size_t info_len)
{
    u_char       t[32];
    u_char       input[32 + 32];
    size_t       t_len, ilen, remaining, chunk;
    unsigned int hlen;
    u_char       counter = 0;

    if (info_len > 32) {
        return NGX_ERROR;
    }

    t_len = 0;
    remaining = out_len;

    while (remaining > 0) {

        counter++;

        if (counter == 0) {
            return NGX_ERROR;
        }

        ilen = 0;

        if (t_len > 0) {
            ngx_memcpy(input, t, t_len);
            ilen = t_len;
        }

        ngx_memcpy(input + ilen, info, info_len);
        ilen += info_len;
        input[ilen++] = counter;

        if (HMAC(digest, prk, (int) prk_len, input, ilen, t, &hlen) == NULL
            || hlen != 32)
        {
            return NGX_ERROR;
        }

        t_len = hlen;

        chunk = (remaining < t_len) ? remaining : t_len;
        ngx_memcpy(out + (out_len - remaining), t, chunk);
        remaining -= chunk;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_qr_hp_mask(u_char *hp_key, u_char *sample, u_char *mask, ngx_log_t *log)
{
    EVP_CIPHER_CTX  *ctx;
    int              outl;
    u_char           out[16];

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp_key, NULL) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_EncryptUpdate(ctx, out, &outl, sample, 16) != 1
        || outl != 16)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    ngx_memcpy(mask, out, NGX_QR_HP_LEN);

    return NGX_OK;
}


static ngx_int_t
ngx_qr_decrypt_initial(u_char *dcid, uint8_t dcid_len,
    u_char *pkt, size_t pkt_len, u_char *plain, size_t plain_size,
    size_t *plain_len, ngx_qr_diag_t *diag, ngx_log_t *log)
{
    u_char       is[32], client_secret[32], key[NGX_QR_KEY_LEN],
                 iv[NGX_QR_IV_LEN], hp[NGX_QR_KEY_LEN];
    size_t       is_len = 32, cs_len = 32;
    u_char      *p, *end, *pn_area, *sample, *ct;
    uint64_t     token_len, payload_len;
    u_char       flags, flags2, mask[NGX_QR_HP_LEN], nonce[NGX_QR_IV_LEN];
    u_char       ad[NGX_QR_AD_MAX];
    uint64_t     pn = 0;
    size_t       ad_len, ct_len;
    int          pnl, i, outl, total = 0, rc;
    uint8_t      dl, sl;
    EVP_CIPHER_CTX  *cctx;

    *plain_len = 0;

    if (pkt_len < 6 || dcid_len == 0) {
        ngx_qr_fail = "pkt-short";
        return NGX_DECLINED;
    }

    /* 1. derive the client Initial keys from the DCID */

    if (ngx_qr_hkdf_extract(is, &is_len, EVP_sha256(),
                            dcid, dcid_len,
                            ngx_qr_initial_salt, NGX_QR_SALT_LEN) != NGX_OK)
    {
        ngx_qr_fail = "hkdf-extract";
        return NGX_DECLINED;
    }

    if (ngx_qr_hkdf_expand_label(client_secret, cs_len, is, is_len,
                                  "client in") != NGX_OK
        || ngx_qr_hkdf_expand_label(key, NGX_QR_KEY_LEN,
                              client_secret, cs_len,
                              "quic key") != NGX_OK
        || ngx_qr_hkdf_expand_label(iv, NGX_QR_IV_LEN,
                              client_secret, cs_len,
                              "quic iv") != NGX_OK
        || ngx_qr_hkdf_expand_label(hp, NGX_QR_KEY_LEN,
                              client_secret, cs_len,
                              "quic hp") != NGX_OK)
    {
        ngx_qr_fail = "hkdf-expand";
        return NGX_DECLINED;
    }

    /* 2. walk the long header to the packet-number area */

    p = pkt;
    end = pkt + pkt_len;

    flags = *p++;

    if ((flags & 0x80) == 0) {
        ngx_qr_fail = "not-long";
        return NGX_DECLINED;
    }

    p += 4;                            /* version */
    diag->version = ((uint32_t) pkt[1] << 24) | ((uint32_t) pkt[2] << 16)
                    | ((uint32_t) pkt[3] << 8) | pkt[4];

    if (((flags >> 4) & 0x03) != 0) {  /* type = bits 5-4 (0x30 mask) */
        ngx_qr_fail = "not-initial";   /* 0-RTT / Handshake / Retry */
        return NGX_DECLINED;           /* not an Initial packet */
    }

    dl = *p++;
    if (dl != dcid_len) {
        ngx_qr_fail = "dcid-len";
        return NGX_DECLINED;
    }
    p += dl;

    sl = *p++;
    p += sl;

    if (p > end) {
        ngx_qr_fail = "hdr-overrun";
        return NGX_DECLINED;
    }

    if (ngx_qr_varint(&p, end, &token_len) != NGX_OK
        || (uint64_t) (end - p) < token_len)
    {
        ngx_qr_fail = "token-varint";
        return NGX_DECLINED;
    }
    p += (size_t) token_len;
    diag->token_len = token_len;

    if (ngx_qr_varint(&p, end, &payload_len) != NGX_OK) {
        ngx_qr_fail = "len-varint";
        return NGX_DECLINED;
    }
    diag->payload_len = payload_len;

    pn_area = p;

    /* bound the packet to its own Length field: client datagrams may
     * coalesce further packets after the Initial */

    if ((uint64_t) (end - pn_area) < payload_len) {
        ngx_qr_fail = "len-overrun";
        return NGX_DECLINED;
    }

    end = pn_area + (size_t) payload_len;

    if (end - pn_area < NGX_QR_TAG_LEN + 4) {
        ngx_qr_fail = "payload-short";
        return NGX_DECLINED;
    }

    /* 3. remove header protection (sample = pn_area + 4, 16 bytes) */

    sample = pn_area + 4;
    if (end - sample < 16) {
        ngx_qr_fail = "sample-short";
        return NGX_DECLINED;
    }

    if (ngx_qr_hp_mask(hp, sample, mask, log) != NGX_OK) {
        ngx_qr_fail = "hp-mask";
        return NGX_DECLINED;
    }

    flags2 = flags ^ (mask[0] & 0x0f);

    pnl = (flags2 & 0x03) + 1;

    for (i = 0; i < pnl; i++) {
        pn = (pn << 8) | (pn_area[i] ^ mask[1 + i]);
    }

    diag->pn = pn;

    /* 4. build the associated data (unprotected header incl. pn field) */

    ad_len = (size_t) (pn_area - pkt) + pnl;
    diag->ad_len = ad_len;
    if (ad_len > sizeof(ad)) {
        ngx_qr_fail = "ad-too-big";    /* header+token > NGX_QR_AD_MAX */
        return NGX_DECLINED;
    }

    ngx_memcpy(ad, pkt, ad_len);
    ad[0] = flags2;
    for (i = 0; i < pnl; i++) {
        ad[ad_len - pnl + i] = (u_char) ((pn >> (8 * (pnl - 1 - i))) & 0xff);
    }

    /* 5. nonce = iv XOR pn (last 4 bytes, big endian) */

    ngx_memcpy(nonce, iv, NGX_QR_IV_LEN);
    for (i = 0; i < 4; i++) {
        nonce[NGX_QR_IV_LEN - 4 + i] ^=
            (u_char) ((pn >> (8 * (3 - i))) & 0xff);
    }

    /* 6. AEAD open */

    ct = pn_area + pnl;
    ct_len = (size_t) (end - ct);

    if (ct_len <= NGX_QR_TAG_LEN) {
        ngx_qr_fail = "ct-short";
        return NGX_DECLINED;
    }

    if (ct_len - NGX_QR_TAG_LEN > plain_size) {
        ngx_qr_fail = "plain-overflow";
        return NGX_DECLINED;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        ngx_qr_fail = "evp-alloc";
        return NGX_DECLINED;
    }

    rc = 0;

    if (EVP_DecryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN,
                               NGX_QR_IV_LEN, NULL) == 1
        && EVP_DecryptInit_ex(cctx, NULL, NULL, key, nonce) == 1
        && EVP_DecryptUpdate(cctx, NULL, &outl, ad, ad_len) == 1)
    {
        if (EVP_DecryptUpdate(cctx, plain, &outl, ct,
                              ct_len - NGX_QR_TAG_LEN) == 1)
        {
            total = outl;

            if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG,
                                    NGX_QR_TAG_LEN, ct + ct_len
                                    - NGX_QR_TAG_LEN) == 1
                && EVP_DecryptFinal_ex(cctx, plain + total, &outl) == 1)
            {
                total += outl;
                rc = 1;
            }
        }
    }

    EVP_CIPHER_CTX_free(cctx);

    if (!rc) {
        ngx_qr_fail = "aead-open";
        return NGX_DECLINED;
    }

    *plain_len = (size_t) total;

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* ClientHello SNI extraction from the decrypted Initial payload */

static ngx_int_t
ngx_qr_extract_sni(u_char *stream, size_t len, ngx_str_t *sni,
    ngx_log_t *log)
{
    u_char    *p, *ch, *ch_end, *c;
    uint64_t   hs_len, ext_type, ext_len;
    uint64_t   sni_list_len, name_type, name_len;
    uint64_t   sid_len, cs_len, cm_len;

    sni->data = NULL;
    sni->len = 0;

#define QR_SNI_FAIL(x)  do { ngx_qr_fail = (x); return NGX_DECLINED; } while (0)

    /* The input is the reassembled CRYPTO stream (offsets 0..len).
     * QUIC CRYPTO frames carry TLS handshake messages WITHOUT the TLS
     * record layer (RFC 9001 section 4): the ClientHello starts directly.
     * The parse below succeeds as soon as the server_name extension is
     * fully present, even if the ClientHello is not complete yet. */

    ch = stream;

    if (len < 9 || ch[0] != 0x01) {          /* ClientHello */
        QR_SNI_FAIL("ch-type");
    }

    hs_len = ((uint64_t) ch[1] << 16) | ((uint64_t) ch[2] << 8) | ch[3];

    /* clamp to the data actually reassembled so far */
    if (ch + 4 + hs_len > stream + len) {
        ch_end = stream + len;
    } else {
        ch_end = ch + 4 + hs_len;
    }

    p = ch + 4;

    if (ch_end - p < 2 + 32 + 1) {
        QR_SNI_FAIL("ch-short");
    }

    p += 2 + 32;                            /* legacy_version + random */

    sid_len = *p++;
    if ((uint64_t) (ch_end - p) < sid_len) {
        QR_SNI_FAIL("sid-short");
    }
    p += sid_len;

    if (ch_end - p < 2) {
        QR_SNI_FAIL("cs-short");
    }
    cs_len = ((uint64_t) p[0] << 8) | p[1];
    p += 2;
    if ((uint64_t) (ch_end - p) < cs_len) {
        QR_SNI_FAIL("cs-overrun");
    }
    p += cs_len;

    if (ch_end - p < 1) {
        QR_SNI_FAIL("cm-short");
    }
    cm_len = *p++;
    if ((uint64_t) (ch_end - p) < cm_len) {
        QR_SNI_FAIL("cm-overrun");
    }
    p += cm_len;

    if (ch_end - p < 2) {
        QR_SNI_FAIL("ext-total-short");
    }
    p += 2;                                 /* extensions total length */

    /* extension loop */

    while ((uint64_t) (ch_end - p) >= 4) {

        ext_type = ((uint64_t) p[0] << 8) | p[1];
        ext_len = ((uint64_t) p[2] << 8) | p[3];
        p += 4;

        if (ext_type == 0 && ext_len >= 5) { /* server_name */

            u_char  *q = p;

            sni_list_len = ((uint64_t) q[0] << 8) | q[1];
            q += 2;

            if (sni_list_len + 2 != ext_len) {
                QR_SNI_FAIL("sni-list-len");
            }

            name_type = *q++;

            if (name_type != 0) {
                QR_SNI_FAIL("sni-type");
            }

            name_len = ((uint64_t) q[0] << 8) | q[1];
            q += 2;

            if (name_len == 0
                || name_len > 255
                || (uint64_t) (p + ext_len - q) < name_len)
            {
                QR_SNI_FAIL("sni-name-len");
            }

            sni->data = q;
            sni->len = (size_t) name_len;

            /* charset sanity: a real SNI is [A-Za-z0-9.-] only.  A
             * mis-reassembled buffer must never become a resolve target
             * ("www.youtube.c\xNN\xNN" must not reach the resolver). */
            for (c = q; c < q + name_len; c++) {
                if (!((*c >= 'a' && *c <= 'z')
                      || (*c >= 'A' && *c <= 'Z')
                      || (*c >= '0' && *c <= '9')
                      || *c == '.' || *c == '-'))
                {
                    QR_SNI_FAIL("sni-charset");
                }
            }

            return NGX_OK;
        }

        if ((uint64_t) (ch_end - p) < ext_len) {
            QR_SNI_FAIL("ext-overrun");
        }

        p += (size_t) ext_len;
    }

    QR_SNI_FAIL("no-sni-ext");
#undef QR_SNI_FAIL
}


/* ---------------------------------------------------------------------- */
/* Session routing: acquire the ClientHello (possibly split across several
 * Initial packets), extract the SNI, start resolution, or fall back. */

static void
ngx_qr_try_route(ngx_qr_session_t *s, u_char *data, size_t len,
    u_char *dcid, uint8_t dcid_len)
{
    size_t               plain_len = 0;
    ngx_str_t            sni;
    ngx_resolver_ctx_t  *rctx;
    ngx_qr_ctx_t        *ctx = s->ctx;
    ngx_qr_srv_conf_t   *conf = s->conf;
    ngx_qr_diag_t        diag;

    if (!conf->sni || ctx->resolver == NULL) {
        goto fallback;
    }

    if (s->plainbuf == NULL) {
        s->plainbuf = ngx_palloc(s->pool, NGX_QR_PLAIN_BUF);
    }

    if (s->crypto == NULL) {
        s->crypto = ngx_palloc(s->pool, NGX_QR_CRYPTO_BUF);
    }

    if (s->plainbuf == NULL || s->crypto == NULL) {
        return;
    }

    ngx_memzero(&diag, sizeof(ngx_qr_diag_t));

    if (ngx_qr_decrypt_initial(dcid, dcid_len, data, len, s->plainbuf,
                               NGX_QR_PLAIN_BUF, &plain_len, &diag,
                               ctx->log)
        == NGX_OK)
    {
        ngx_log_error(NGX_LOG_DEBUG, ctx->log, 0,
                      "quic_relay: initial decrypted, %uz bytes plain",
                      plain_len);

        (void) ngx_qr_collect_crypto(s, s->plainbuf, plain_len);

    } else {
        /* every decline reason is now visible: this was the blind spot
         * that hid token-carrying Initials (AAD > 128) in the field */
        ctx->decrypt_fail++;

        if (s->decrypt_fail_logged < 3) {
            s->decrypt_fail_logged++;
            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                          "quic_relay: initial decrypt failed (%s):"
                          " ver=0x%uxD pn=%uL token=%uL adlen=%uz"
                          " payload=%uL dgram=%uz dcid_len=%ui",
                          ngx_qr_fail, (ngx_uint_t) diag.version, diag.pn,
                          diag.token_len, diag.ad_len, diag.payload_len,
                          len, (ngx_uint_t) dcid_len);
        } else {
            ngx_log_error(NGX_LOG_DEBUG, ctx->log, 0,
                          "quic_relay: initial decrypt failed (%s):"
                          " ver=0x%uxD pn=%uL token=%uL adlen=%uz",
                          ngx_qr_fail, (ngx_uint_t) diag.version, diag.pn,
                          diag.token_len, diag.ad_len);
        }
    }

    if (s->crypto_len > 0
        && ngx_qr_extract_sni(s->crypto, s->crypto_len, &sni, ctx->log)
           == NGX_OK)
    {
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                      "quic_relay: SNI extracted: %V (crypto %uz bytes,"
                      " %ui Initials)",
                      &sni, s->crypto_len,
                      (ngx_uint_t) s->initials_seen + 1);

        s->sni.data = ngx_pnalloc(s->pool, sni.len);
        if (s->sni.data != NULL) {
            ngx_memcpy(s->sni.data, sni.data, sni.len);
            s->sni.len = sni.len;
            s->sni_ok = 1;
            ctx->sni_ok++;

            rctx = ngx_resolve_start(ctx->resolver, NULL);
            if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
                ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                              "quic_relay: resolver start failed");
                return;
            }

            rctx->name = s->sni;
            rctx->handler = ngx_qr_resolve_handler;
            rctx->data = s;
            s->resolving = 1;
            s->rctx = rctx;

            if (ngx_resolve_name(rctx) != NGX_ERROR) {
                /* early packets are buffered by ngx_qr_forward()
                 * while resolving */
                return;
            }

            s->resolving = 0;
            s->rctx = NULL;

            goto fallback;
        }
    }

    s->initials_seen++;

    if (s->initials_seen < NGX_QR_PENDING_MAX) {
        return;      /* stay pending: more Initials may complete the CH */
    }

    ctx->sni_fail++;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "quic_relay: no SNI after %ui Initials (last fail \"%s\","
                  " crypto %uz bytes)",
                  (ngx_uint_t) s->initials_seen, ngx_qr_fail,
                  s->crypto_len);

fallback:

    if (conf->fallback_addr != NULL && s->upstream_fd == -1
        && !s->resolving)
    {
        ngx_qr_open_upstream(s, conf->fallback_addr,
                             conf->fallback_socklen);
    }
}


static ngx_int_t
ngx_qr_collect_crypto(ngx_qr_session_t *s, u_char *plain, size_t plain_len)
{
    u_char    *p = plain, *end = plain + plain_len;
    uint64_t   ftype, foff, flen, v1, v2, v3, v4;

    while (p < end) {

        if (ngx_qr_varint(&p, end, &ftype) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ftype == 0x00 || ftype == 0x01) {
            /* PADDING / PING: single byte, no length field */
            continue;
        }

        if (ftype == 0x02 || ftype == 0x03) {
            /* ACK: Largest(v) Delay(v) RangeCount(v) FirstRange(v)
             *      + RangeCount * (Gap(v) + Range(v))
             * ACK_ECN appends ECT0(v) ECT1(v) CE(v) */
            if (ngx_qr_varint(&p, end, &v1) != NGX_OK
                || ngx_qr_varint(&p, end, &v2) != NGX_OK
                || ngx_qr_varint(&p, end, &v3) != NGX_OK
                || ngx_qr_varint(&p, end, &v4) != NGX_OK)
            {
                return NGX_ERROR;
            }

            for ( ; v3 > 0; v3--) {
                if (ngx_qr_varint(&p, end, &v1) != NGX_OK
                    || ngx_qr_varint(&p, end, &v2) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            if (ftype == 0x03) {
                if (ngx_qr_varint(&p, end, &v1) != NGX_OK
                    || ngx_qr_varint(&p, end, &v2) != NGX_OK
                    || ngx_qr_varint(&p, end, &v4) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            continue;
        }

        if (ftype == 0x06) {                /* CRYPTO */

            if (ngx_qr_varint(&p, end, &foff) != NGX_OK
                || ngx_qr_varint(&p, end, &flen) != NGX_OK
                || (uint64_t) (end - p) < flen)
            {
                return NGX_ERROR;
            }

            if (foff <= (uint64_t) s->crypto_len) {

                if (foff + flen > (uint64_t) s->crypto_len) {
                    /* extends the contiguous prefix: append in place,
                     * then drain any stash that just became contiguous */
                    (void) ngx_qr_crypto_append(s, p, flen, foff);
                }
                /* else: pure duplicate of what we already have */

            } else if (flen <= NGX_QR_HOLE_MAX
                       && foff < NGX_QR_CRYPTO_BUF)
            {
                /* future offset: hold it until the gap is filled */
                ngx_qr_crypto_stash(s, p, (size_t) flen, foff);
            }

            p += (size_t) flen;
            continue;
        }

        if (ftype == 0x1c) {                /* CONNECTION_CLOSE:
                                               Error(v) FrameType(v)
                                               ReasonLen(v) Reason */
            if (ngx_qr_varint(&p, end, &v1) != NGX_OK
                || ngx_qr_varint(&p, end, &v2) != NGX_OK
                || ngx_qr_varint(&p, end, &v3) != NGX_OK
                || (uint64_t) (end - p) < v3)
            {
                return NGX_ERROR;
            }
            p += (size_t) v3;
            continue;
        }

        /* Only PADDING, PING, ACK, ACK_ECN, CRYPTO and CONNECTION_CLOSE
         * are legal in client Initials (RFC 9001 section 4.6).  Anything
         * else means we lost frame sync (or a non-Initial slipped in):
         * stop walking instead of guessing a length and mis-reassembling
         * CRYPTO data at bogus offsets.  Frames already collected stay
         * valid. */

        s->ctx->frame_err++;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_qr_crypto_append(ngx_qr_session_t *s, u_char *data, uint64_t flen,
    uint64_t foff)
{
    size_t     chunk;
    uint64_t   i, n;

    /* append the tail of [foff, foff+flen) that extends crypto_len */

    chunk = (size_t) (foff + flen - (uint64_t) s->crypto_len);
    if (chunk > (size_t) (NGX_QR_CRYPTO_BUF - s->crypto_len)) {
        chunk = NGX_QR_CRYPTO_BUF - s->crypto_len;
    }

    ngx_memcpy(s->crypto + s->crypto_len,
               data + (size_t) ((uint64_t) s->crypto_len - foff),
               chunk);
    s->crypto_len += chunk;

    /* drain stashed out-of-order chunks that are now contiguous */

    for ( ;; ) {
        n = (uint64_t) s->crypto_len;

        for (i = 0; i < NGX_QR_MAX_HOLES; i++) {
            if (s->hole_len[i] == 0) {
                continue;
            }

            if (s->hole_off[i] <= n
                && s->hole_off[i] + s->hole_len[i] > n)
            {
                chunk = (size_t) (s->hole_off[i] + s->hole_len[i] - n);
                if (chunk > (size_t) (NGX_QR_CRYPTO_BUF - s->crypto_len)) {
                    chunk = NGX_QR_CRYPTO_BUF - s->crypto_len;
                }

                ngx_memcpy(s->crypto + s->crypto_len,
                           s->hole_buf + i * NGX_QR_HOLE_MAX
                           + (size_t) (n - s->hole_off[i]),
                           chunk);
                s->crypto_len += chunk;
                s->hole_len[i] = 0;
                break;              /* rescan from the first slot */
            }
        }

        if ((uint64_t) s->crypto_len == n) {
            break;                  /* nothing more is contiguous */
        }
    }

    return NGX_OK;
}


static void
ngx_qr_crypto_stash(ngx_qr_session_t *s, u_char *data, size_t flen,
    uint64_t foff)
{
    size_t   i;

    if (s->hole_buf == NULL) {
        s->hole_buf = ngx_palloc(s->pool,
                                 NGX_QR_MAX_HOLES * NGX_QR_HOLE_MAX);
        if (s->hole_buf == NULL) {
            return;
        }
    }

    for (i = 0; i < NGX_QR_MAX_HOLES; i++) {
        if (s->hole_len[i] == 0) {
            s->hole_off[i] = foff;
            s->hole_len[i] = flen;
            ngx_memcpy(s->hole_buf + i * NGX_QR_HOLE_MAX, data, flen);
            return;
        }
    }

    /* no free slot: the chunk is dropped; the prefix parse still
     * succeeds as long as the SNI lies inside the contiguous part */
}


static void
ngx_qr_noop(ngx_event_t *ev)
{
    /* nothing: upstream udp sockets are always writable */
}
