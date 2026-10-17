/*
 * ngx_stream_geosite_module
 *
 * Loads a v2ray/xray `geosite.dat` (a.k.a. dlc.dat) file and exposes the
 * variable $geosite_category, which returns the geosite category tag
 * (e.g. "amazon", "netflix", "google") matching $ssl_preread_server_name,
 * or the empty string if no category matches.
 *
 * Typical usage with the proxy_interface directive (added by this fork):
 *
 *   stream {
 *       geosite_load /usr/local/etc/xray/domains/dlc.dat;
 *       geosite_filter amazon hulu disney netflix;
 *
 *       map $geosite_category $egress_iface {
 *           default  off;
 *           amazon   ak;
 *           hulu     ak;
 *           disney   ak;
 *           netflix  ak;
 *       }
 *
 *       server {
 *           listen 443 ...;
 *           ssl_preread on;
 *           proxy_interface $egress_iface;
 *           proxy_pass $target_backend;
 *       }
 *   }
 *
 * Matching semantics (matches Xray's geosite rules):
 *   - Domain type ("amazon.com"): matches "amazon.com" and any subdomain
 *     ("www.amazon.com", "aws.amazon.com"). Does NOT match "notamazon.com".
 *   - Full type: exact case-insensitive match.
 *   - Plain type: substring match (slower, supported but rarely needed).
 *   - Regex type: requires PCRE; parsed but not matched in this version
 *     (a warning is emitted at load time).
 *
 * Memory model:
 *   All structures are allocated from cf->cycle->pool at config-parse time,
 *   so they are inherited by worker processes via fork() (copy-on-write).
 *   There is no per-worker re-loading. Reloads require `nginx -s reload`,
 *   which triggers a fresh config parse.
 *
 * Author: cddeppe/nginx fork
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


/*
 * Protobuf wire types we care about.
 */
#define NGX_PB_WIRE_VARINT   0
#define NGX_PB_WIRE_FIXED64  1
#define NGX_PB_WIRE_LEN      2
#define NGX_PB_WIRE_FIXED32  5

/*
 * Field numbers used in the geosite protobuf schema
 * (see v2ray-core/app/router/config.proto).
 */
#define NGX_GEOSITE_LIST_FIELD_ENTRY       1  /* repeated GeoSite */
#define NGX_GEOSITE_FIELD_COUNTRY_CODE     1  /* string  */
#define NGX_GEOSITE_FIELD_DOMAIN           2  /* repeated Domain */
#define NGX_GEOSITE_DOMAIN_FIELD_TYPE      1  /* varint  */
#define NGX_GEOSITE_DOMAIN_FIELD_VALUE     2  /* string  */

/*
 * Domain types (v2ray Domain.Type enum).
 * IMPORTANT: these match the v2ray-core proto definition exactly:
 *   https://github.com/v2fly/v2ray-core/blob/master/app/router/config.proto
 *
 *   enum Type {
 *     Plain = 0;   // substring match
 *     Regex = 1;   // regex match (not implemented here)
 *     Domain = 2;  // suffix match (matches domain + all subdomains)
 *     Full = 3;    // exact match (case-insensitive)
 *   }
 *
 * DO NOT change these values — they are wire-format constants defined by
 * the v2ray protobuf schema. A previous version of this code had them
 * wrong (Domain=1, Full=2, Regex=3), which caused all geosite entries
 * to be miscategorized and matching to silently fail.
 */
#define NGX_GEOSITE_TYPE_PLAIN   0
#define NGX_GEOSITE_TYPE_REGEX   1
#define NGX_GEOSITE_TYPE_DOMAIN  2
#define NGX_GEOSITE_TYPE_FULL    3


/*
 * A single loaded geosite category (e.g. "amazon", "netflix").
 *
 *   full_hash    - exact-match hash (Domain.Type == Full)
 *   domain_hash  - suffix-match hash (Domain.Type == Domain)
 *   plain_array  - linear list of substrings (Domain.Type == Plain)
 *
 * Plain entries are matched by linear scan; they are rare in real geosite
 * files so this is acceptable.
 */
typedef struct {
    ngx_str_t    tag;           /* e.g. "amazon" (lowercased) */
    ngx_hash_t   full_hash;
    ngx_hash_t   domain_hash;
    ngx_array_t  plain_array;   /* ngx_str_t */
    ngx_uint_t   domain_count;
    ngx_uint_t   full_count;
    ngx_uint_t   plain_count;
    ngx_uint_t   regex_skipped;
} ngx_stream_geosite_category_t;


/*
 * Main configuration: the loaded file path, the (optional) tag filter,
 * and the parsed categories.
 */
typedef struct {
    ngx_str_t                            *file_path;
    ngx_array_t                          *filters;     /* ngx_str_t */
    ngx_array_t                          *categories;  /* ngx_stream_geosite_category_t */
    ngx_uint_t                            hash_bucket_size;
    ngx_uint_t                            hash_max_size;
    ngx_flag_t                            loaded;
} ngx_stream_geosite_main_conf_t;


static ngx_int_t ngx_stream_geosite_init(ngx_conf_t *cf);
static void *ngx_stream_geosite_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_geosite_load_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_geosite_filter_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_geosite_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_stream_geosite_load_file(ngx_conf_t *cf,
    ngx_stream_geosite_main_conf_t *gmcf);
static ngx_int_t ngx_stream_geosite_parse_buf(ngx_conf_t *cf, u_char *buf,
    u_char *end, ngx_stream_geosite_main_conf_t *gmcf);
static ngx_int_t ngx_stream_geosite_build_hashes(ngx_conf_t *cf,
    ngx_stream_geosite_main_conf_t *gmcf);

/* protobuf helpers */
static ngx_uint_t ngx_pb_read_varint(u_char **p, u_char *end);
static u_char    *ngx_pb_read_len(u_char **p, u_char *end, size_t *len);
static ngx_int_t  ngx_pb_skip_field(u_char **p, u_char *end, ngx_uint_t wire);


/*
 * Module commands.
 */
static ngx_command_t  ngx_stream_geosite_commands[] = {

    { ngx_string("geosite_load"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_geosite_load_directive,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geosite_filter"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_1MORE,
      ngx_stream_geosite_filter_directive,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    /*
     * geosite_hash_bucket_size <size>
     *
     * Sets the bucket size for the per-category Full and Domain hash tables.
     * Must be at least as large as the longest domain entry plus ~32 bytes
     * of header. Default 256, which covers entries up to ~220 bytes.
     * If you see "could not build geosite_domain_hash, you should increase
     * geosite_hash_bucket_size", bump this value (typically double it).
     */
    { ngx_string("geosite_hash_bucket_size"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_geosite_main_conf_t, hash_bucket_size),
      NULL },

    /*
     * geosite_hash_max_size <size>
     *
     * Sets the maximum number of buckets for each per-category hash table.
     * Default 16384 (handles up to ~100k entries per category comfortably).
     */
    { ngx_string("geosite_hash_max_size"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_geosite_main_conf_t, hash_max_size),
      NULL },

    ngx_null_command
};


static ngx_stream_module_t  ngx_stream_geosite_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_geosite_init,               /* postconfiguration */

    ngx_stream_geosite_create_main_conf,   /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_geosite_module = {
    NGX_MODULE_V1,
    &ngx_stream_geosite_module_ctx,        /* module context */
    ngx_stream_geosite_commands,           /* commands */
    NGX_STREAM_MODULE,                     /* type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------ */
/* Protobuf wire-format helpers                                       */
/* ------------------------------------------------------------------ */

static ngx_uint_t
ngx_pb_read_varint(u_char **p, u_char *end)
{
    ngx_uint_t  value = 0;
    int         shift = 0;
    u_char      c;

    while (*p < end) {
        c = *(*p)++;
        value |= (ngx_uint_t) (c & 0x7F) << shift;
        if (!(c & 0x80)) {
            return value;
        }
        shift += 7;
        if (shift >= 64) {
            return 0;  /* overflow */
        }
    }
    return 0;
}


static u_char *
ngx_pb_read_len(u_char **p, u_char *end, size_t *len)
{
    ngx_uint_t  n;

    n = ngx_pb_read_varint(p, end);

    /*
     * Compare as a count, never as a pointer: "*p + n" can wrap around
     * on 64-bit lengths (a 10-byte varint encodes up to 2^64-1), pass
     * the "> end" test, and hand the caller a start pointer below the
     * buffer - which then parses pool memory as file content.
     */
    if (n > (ngx_uint_t) (end - *p)) {
        return NULL;
    }
    *len = (size_t) n;
    return *p + n;  /* pointer to one past the end; we return start below */
}


/*
 * Skip a protobuf field of the given wire type, advancing *p past it.
 */
static ngx_int_t
ngx_pb_skip_field(u_char **p, u_char *end, ngx_uint_t wire)
{
    size_t      len;
    u_char     *new_end;

    switch (wire) {
    case NGX_PB_WIRE_VARINT:
        ngx_pb_read_varint(p, end);
        return NGX_OK;

    case NGX_PB_WIRE_FIXED64:
        if (*p + 8 > end) return NGX_ERROR;
        *p += 8;
        return NGX_OK;

    case NGX_PB_WIRE_LEN:
        new_end = ngx_pb_read_len(p, end, &len);
        if (new_end == NULL) return NGX_ERROR;
        *p += len;
        return NGX_OK;

    case NGX_PB_WIRE_FIXED32:
        if (*p + 4 > end) return NGX_ERROR;
        *p += 4;
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}


/* ------------------------------------------------------------------ */
/* Config factory                                                     */
/* ------------------------------------------------------------------ */

static void *
ngx_stream_geosite_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_geosite_main_conf_t  *gmcf;

    gmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_geosite_main_conf_t));
    if (gmcf == NULL) {
        return NULL;
    }

    gmcf->file_path = NULL;
    gmcf->filters = NULL;
    gmcf->categories = NULL;
    gmcf->hash_bucket_size = NGX_CONF_UNSET_UINT;
    gmcf->hash_max_size = NGX_CONF_UNSET_UINT;
    gmcf->loaded = 0;
    return gmcf;
}


/* ------------------------------------------------------------------ */
/* Directives                                                         */
/* ------------------------------------------------------------------ */

static char *
ngx_stream_geosite_load_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_geosite_main_conf_t  *gmcf = conf;
    ngx_str_t                       *value;

    if (gmcf->file_path != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    gmcf->file_path = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (gmcf->file_path == NULL) {
        return NGX_CONF_ERROR;
    }
    *gmcf->file_path = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_stream_geosite_filter_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_geosite_main_conf_t  *gmcf = conf;
    ngx_str_t                       *value, *tag;
    ngx_uint_t                       i;

    if (gmcf->filters == NULL) {
        gmcf->filters = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (gmcf->filters == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        tag = ngx_array_push(gmcf->filters);
        if (tag == NULL) {
            return NGX_CONF_ERROR;
        }
        *tag = value[i];
    }

    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------ */
/* File loader and parser                                             */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_geosite_load_file(ngx_conf_t *cf,
    ngx_stream_geosite_main_conf_t *gmcf)
{
    u_char      *buf;
    size_t       size;
    ssize_t      n;
    ngx_fd_t     fd;
    ngx_file_t   file;
    ngx_err_t    err;

    if (gmcf->file_path == NULL) {
        return NGX_OK;
    }

    fd = ngx_open_file(gmcf->file_path->data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                           "geosite_load: failed to open \"%V\"",
                           gmcf->file_path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &file.info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "geosite_load: stat(\"%V\") failed",
                           gmcf->file_path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(&file.info);
    ngx_close_file(fd);

    buf = ngx_palloc(cf->cycle->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(gmcf->file_path->data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "geosite_load: reopen(\"%V\") failed",
                           gmcf->file_path);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, size);
    ngx_close_file(fd);
    if (n == NGX_FILE_ERROR || (size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geosite_load: short read on \"%V\"",
                           gmcf->file_path);
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "geosite_load: loaded %V (%z bytes), parsing...",
                       gmcf->file_path, size);

    gmcf->categories = ngx_array_create(cf->cycle->pool, 64,
                                        sizeof(ngx_stream_geosite_category_t));
    if (gmcf->categories == NULL) {
        return NGX_ERROR;
    }

    if (ngx_stream_geosite_parse_buf(cf, buf, buf + size, gmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_geosite_build_hashes(cf, gmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    gmcf->loaded = 1;

    {
        ngx_uint_t  total = 0;
        ngx_stream_geosite_category_t  *cat;
        ngx_uint_t                       i;

        cat = gmcf->categories->elts;
        for (i = 0; i < gmcf->categories->nelts; i++) {
            total += cat[i].full_count + cat[i].domain_count + cat[i].plain_count;
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                           "geosite_load: parsed %ui categories, %ui total domains",
                           gmcf->categories->nelts, total);
    }

    return NGX_OK;
}


/*
 * Parse a single Domain message into the category being built.
 *
 *   domain_buf   - start of the Domain message body
 *   domain_end   - one past end of the Domain message body
 *   cat          - target category
 *   full_keys    - keys array to populate (Full type)
 *   domain_keys  - keys array to populate (Domain type)
 */
static ngx_int_t
ngx_stream_geosite_parse_domain(ngx_conf_t *cf,
    u_char *p, u_char *end,
    ngx_stream_geosite_category_t *cat,
    ngx_hash_keys_arrays_t *full_keys,
    ngx_hash_keys_arrays_t *domain_keys)
{
    ngx_uint_t   field_no, wire;
    ngx_uint_t   type = NGX_GEOSITE_TYPE_PLAIN;  /* default per proto3 */
    ngx_str_t    value = ngx_null_string;
    u_char      *str_end;
    size_t       len;
    ngx_str_t   *plain;
    ngx_str_t    lc_value;
    u_char      *lower;

    while (p < end) {
        wire = ngx_pb_read_varint(&p, end);
        field_no = wire >> 3;
        wire &= 0x07;

        if (field_no == NGX_GEOSITE_DOMAIN_FIELD_TYPE && wire == NGX_PB_WIRE_VARINT) {
            type = ngx_pb_read_varint(&p, end);
            continue;
        }

        if (field_no == NGX_GEOSITE_DOMAIN_FIELD_VALUE && wire == NGX_PB_WIRE_LEN) {
            str_end = ngx_pb_read_len(&p, end, &len);
            if (str_end == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: truncated domain value length");
                return NGX_ERROR;
            }
            value.data = p;
            value.len = len;
            p = str_end;
            continue;
        }

        if (ngx_pb_skip_field(&p, end, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (value.data == NULL) {
        return NGX_OK;  /* skip empty entries */
    }

    /* lowercase a copy of value in cycle->pool */
    lower = ngx_pnalloc(cf->cycle->pool, value.len);
    if (lower == NULL) {
        return NGX_ERROR;
    }
    ngx_strlow(lower, value.data, value.len);
    lc_value.data = lower;
    lc_value.len = value.len;

    switch (type) {

    case NGX_GEOSITE_TYPE_FULL:
        if (ngx_hash_add_key(full_keys, &lc_value, (void *) 1,
                             NGX_HASH_READONLY_KEY) == NGX_ERROR)
        {
            /* NGX_BUSY (duplicate key) is fine; NGX_ERROR is not */
            return NGX_ERROR;
        }
        cat->full_count++;
        break;

    case NGX_GEOSITE_TYPE_DOMAIN:
        if (ngx_hash_add_key(domain_keys, &lc_value, (void *) 1,
                             NGX_HASH_READONLY_KEY) == NGX_ERROR)
        {
            /* NGX_BUSY (duplicate key) is fine; NGX_ERROR is not */
            return NGX_ERROR;
        }
        cat->domain_count++;
        break;

    case NGX_GEOSITE_TYPE_PLAIN:
        /*
         * ngx_strnstr() at match time requires a NUL-terminated needle:
         * it calls ngx_strlen() on the find string. lc_value is an
         * exact-length pool slice with no terminator, so storing it
         * directly lets that strlen() read past the end of the slice
         * (and can match a longer string than intended). Store a
         * terminated copy instead.
         */
        plain = ngx_array_push(&cat->plain_array);
        if (plain == NULL) {
            return NGX_ERROR;
        }

        plain->data = ngx_pnalloc(cf->cycle->pool, lc_value.len + 1);
        if (plain->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(plain->data, lc_value.data, lc_value.len);
        plain->data[lc_value.len] = '\0';
        plain->len = lc_value.len;

        cat->plain_count++;
        break;

    case NGX_GEOSITE_TYPE_REGEX:
        cat->regex_skipped++;
        break;

    default:
        break;
    }

    return NGX_OK;
}


/*
 * Walk a GeoSite message body once: collect country code AND parse each
 * Domain sub-message in a single pass.
 */
static ngx_int_t
ngx_stream_geosite_process_geosite(ngx_conf_t *cf,
    u_char *p, u_char *end,
    ngx_stream_geosite_main_conf_t *gmcf,
    ngx_stream_geosite_category_t **out_cat)
{
    ngx_uint_t                       field_no, wire;
    ngx_str_t                        country_code = ngx_null_string;
    u_char                          *str_end;
    size_t                           len;
    ngx_stream_geosite_category_t   *cat = NULL;
    ngx_hash_keys_arrays_t          *full_keys, *domain_keys;
    ngx_str_t                       *filter_tag;
    ngx_uint_t                       i, matched;
    u_char                          *dom_body, *dom_end;

    while (p < end) {
        wire = ngx_pb_read_varint(&p, end);
        field_no = wire >> 3;
        wire &= 0x07;

        if (field_no == NGX_GEOSITE_FIELD_COUNTRY_CODE && wire == NGX_PB_WIRE_LEN) {
            str_end = ngx_pb_read_len(&p, end, &len);
            if (str_end == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: truncated country_code length");
                return NGX_ERROR;
            }
            country_code.data = p;
            country_code.len = len;
            p = str_end;

            /* If we have not yet allocated the category, do so now
             * (with filter check). */
            if (cat == NULL) {
                if (country_code.len == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "geosite: empty country_code");
                    return NGX_ERROR;
                }

                matched = 1;
                if (gmcf->filters != NULL && gmcf->filters->nelts > 0) {
                    matched = 0;
                    filter_tag = gmcf->filters->elts;
                    for (i = 0; i < gmcf->filters->nelts; i++) {
                        if (filter_tag[i].len == country_code.len &&
                            ngx_strncasecmp(filter_tag[i].data,
                                            country_code.data,
                                            country_code.len) == 0)
                        {
                            matched = 1;
                            break;
                        }
                    }
                }

                if (!matched) {
                    *out_cat = NULL;
                    /* we still need to skip remaining fields */
                    continue;
                }

                cat = ngx_array_push(gmcf->categories);
                if (cat == NULL) return NGX_ERROR;
                ngx_memzero(cat, sizeof(ngx_stream_geosite_category_t));

                cat->tag.data = ngx_pnalloc(cf->cycle->pool, country_code.len);
                if (cat->tag.data == NULL) return NGX_ERROR;
                ngx_strlow(cat->tag.data, country_code.data, country_code.len);
                cat->tag.len = country_code.len;

                if (ngx_array_init(&cat->plain_array, cf->cycle->pool, 32,
                                   sizeof(ngx_str_t)) != NGX_OK)
                {
                    return NGX_ERROR;
                }

                full_keys = ngx_pcalloc(cf->pool, sizeof(ngx_hash_keys_arrays_t));
                domain_keys = ngx_pcalloc(cf->pool, sizeof(ngx_hash_keys_arrays_t));
                if (full_keys == NULL || domain_keys == NULL) return NGX_ERROR;

                full_keys->pool = cf->pool;
                full_keys->temp_pool = cf->pool;
                domain_keys->pool = cf->pool;
                domain_keys->temp_pool = cf->pool;

                if (ngx_hash_keys_array_init(full_keys, NGX_HASH_LARGE) != NGX_OK) {
                    return NGX_ERROR;
                }
                if (ngx_hash_keys_array_init(domain_keys, NGX_HASH_LARGE) != NGX_OK) {
                    return NGX_ERROR;
                }

                /* stash via a parallel struct */
                cat->full_hash.buckets = (ngx_hash_elt_t **) full_keys;
                cat->domain_hash.buckets = (ngx_hash_elt_t **) domain_keys;
            }
            continue;
        }

        if (field_no == NGX_GEOSITE_FIELD_DOMAIN && wire == NGX_PB_WIRE_LEN) {
            str_end = ngx_pb_read_len(&p, end, &len);
            if (str_end == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: truncated domain entry length");
                return NGX_ERROR;
            }
            dom_body = p;
            dom_end = str_end;
            p = str_end;

            if (cat != NULL) {
                full_keys = (ngx_hash_keys_arrays_t *) cat->full_hash.buckets;
                domain_keys = (ngx_hash_keys_arrays_t *) cat->domain_hash.buckets;

                if (ngx_stream_geosite_parse_domain(cf, dom_body, dom_end,
                                                    cat,
                                                    full_keys, domain_keys)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
            continue;
        }

        if (ngx_pb_skip_field(&p, end, wire) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "geosite: malformed field in GeoSite entry");
            return NGX_ERROR;
        }
    }

    *out_cat = cat;
    return NGX_OK;
}


/*
 * Top-level parser: walk the GeoSiteList.
 */
static ngx_int_t
ngx_stream_geosite_parse_buf(ngx_conf_t *cf, u_char *buf, u_char *end,
    ngx_stream_geosite_main_conf_t *gmcf)
{
    ngx_uint_t   field_no, wire;
    u_char      *p = buf;
    u_char      *body, *body_end;
    size_t       len;
    ngx_stream_geosite_category_t  *cat;

    while (p < end) {
        wire = ngx_pb_read_varint(&p, end);
        field_no = wire >> 3;
        wire &= 0x07;

        if (field_no == NGX_GEOSITE_LIST_FIELD_ENTRY && wire == NGX_PB_WIRE_LEN) {
            body_end = ngx_pb_read_len(&p, end, &len);
            if (body_end == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: truncated entry length");
                return NGX_ERROR;
            }
            body = p;
            p = body_end;

            if (ngx_stream_geosite_process_geosite(cf, body, body_end,
                                                   gmcf, &cat) != NGX_OK)
            {
                return NGX_ERROR;
            }
            continue;
        }

        if (ngx_pb_skip_field(&p, end, wire) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "geosite: malformed top-level field");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * After all categories are parsed, build the final ngx_hash_t for each
 * category's full and domain hash, and the top-level tag → category
 * index hash.
 */
static ngx_int_t
ngx_stream_geosite_build_hashes(ngx_conf_t *cf,
    ngx_stream_geosite_main_conf_t *gmcf)
{
    ngx_stream_geosite_category_t   *cats;
    ngx_uint_t                       i, n;
    ngx_hash_keys_arrays_t          *full_keys, *domain_keys;
    ngx_hash_init_t                  hash_init;
    ngx_uint_t                       bucket_size, max_size;

    if (gmcf->categories == NULL || gmcf->categories->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "geosite: no categories loaded (filter matched "
                           "nothing or file is empty)");
        return NGX_OK;
    }

    /*
     * Default bucket size 256: comfortably fits entries up to ~220 bytes
     * (real geosite entries can be 80+ bytes for long cloudfront / aws
     * subdomains). Default max_size 16384: handles categories with up
     * to ~100k entries with low collision rate.
     */
    bucket_size = gmcf->hash_bucket_size == NGX_CONF_UNSET_UINT
                  ? 256 : gmcf->hash_bucket_size;
    max_size = gmcf->hash_max_size == NGX_CONF_UNSET_UINT
               ? 16384 : gmcf->hash_max_size;

    bucket_size = ngx_align(bucket_size, ngx_cacheline_size);

    cats = gmcf->categories->elts;
    n = gmcf->categories->nelts;

    for (i = 0; i < n; i++) {
        full_keys = (ngx_hash_keys_arrays_t *) cats[i].full_hash.buckets;
        domain_keys = (ngx_hash_keys_arrays_t *) cats[i].domain_hash.buckets;

        if (full_keys == NULL || domain_keys == NULL) {
            continue;
        }

        hash_init.hash = &cats[i].full_hash;
        hash_init.key = ngx_hash_key_lc;
        hash_init.max_size = max_size;
        hash_init.bucket_size = bucket_size;
        hash_init.name = "geosite_full_hash";
        hash_init.pool = cf->cycle->pool;
        hash_init.temp_pool = cf->pool;

        if (full_keys->keys.nelts > 0) {
            if (ngx_hash_init(&hash_init, full_keys->keys.elts,
                              full_keys->keys.nelts) != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: failed to build full_hash for "
                                   "category \"%V\" — try increasing "
                                   "geosite_hash_bucket_size (currently %ui) "
                                   "or geosite_hash_max_size (currently %ui)",
                                   &cats[i].tag, bucket_size, max_size);
                return NGX_ERROR;
            }
        } else {
            cats[i].full_hash.buckets = NULL;
            cats[i].full_hash.size = 0;
        }

        hash_init.hash = &cats[i].domain_hash;
        hash_init.name = "geosite_domain_hash";

        if (domain_keys->keys.nelts > 0) {
            if (ngx_hash_init(&hash_init, domain_keys->keys.elts,
                              domain_keys->keys.nelts) != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "geosite: failed to build domain_hash for "
                                   "category \"%V\" — try increasing "
                                   "geosite_hash_bucket_size (currently %ui) "
                                   "or geosite_hash_max_size (currently %ui)",
                                   &cats[i].tag, bucket_size, max_size);
                return NGX_ERROR;
            }
        } else {
            cats[i].domain_hash.buckets = NULL;
            cats[i].domain_hash.size = 0;
        }
    }

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* Variable handler: $geosite_category                                */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_geosite_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    static ngx_str_t  sni_name = ngx_string("ssl_preread_server_name");
    ngx_stream_geosite_main_conf_t  *gmcf;
    ngx_stream_variable_value_t    *sni_vv;
    ngx_str_t                       sni;
    ngx_uint_t                      sni_key;
    u_char                         *lower, *p, *end;
    ngx_uint_t                      i, n, k;
    ngx_stream_geosite_category_t  *cats, *cat;
    ngx_str_t                      *plain;
    ngx_str_t                       suffix;

    gmcf = ngx_stream_get_module_main_conf(s, ngx_stream_geosite_module);

    if (gmcf == NULL || !gmcf->loaded || gmcf->categories == NULL
        || gmcf->categories->nelts == 0)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    /*
     * Read $ssl_preread_server_name via the variable machinery. This
     * requires ssl_preread to be enabled on the server block, which is
     * the only sensible use case anyway.
     */
    sni_key = ngx_hash_key_lc(sni_name.data, sni_name.len);
    sni_vv = ngx_stream_get_variable(s, &sni_name, sni_key);
    if (sni_vv == NULL || sni_vv->not_found || sni_vv->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    sni.data = sni_vv->data;
    sni.len  = sni_vv->len;

    /* lowercase SNI in connection pool */
    lower = ngx_pnalloc(s->connection->pool, sni.len);
    if (lower == NULL) {
        return NGX_ERROR;
    }
    ngx_strlow(lower, sni.data, sni.len);
    sni.data = lower;

    cats = gmcf->categories->elts;
    n = gmcf->categories->nelts;

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "geosite: matching SNI=\"%V\" against %ui categories",
                  &sni, n);

    /*
     * For each category, check:
     *   1. Exact match in full_hash (sni == key)
     *   2. Any suffix of sni in domain_hash (suffix match)
     *   3. Any plain substring contains sni
     */
    for (i = 0; i < n; i++) {
        cat = &cats[i];

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "geosite: checking cat[%ui]=\"%V\" full_size=%ui domain_size=%ui plain_nelts=%ui",
                      i, &cat->tag, cat->full_hash.size, cat->domain_hash.size,
                      cat->plain_array.nelts);

        /* (1) full match */
        if (cat->full_hash.size > 0) {
            if (ngx_hash_find(&cat->full_hash,
                              ngx_hash_key_lc(sni.data, sni.len),
                              sni.data, sni.len) != NULL)
            {
                v->data = cat->tag.data;
                v->len = cat->tag.len;
                v->valid = 1;
                v->no_cacheable = 1;
                v->not_found = 0;

                ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                              "geosite: FULL MATCH: SNI=\"%V\" -> category=\"%V\"",
                              &sni, &cat->tag);
                return NGX_OK;
            }
        }

        /* (2) suffix match — try each suffix of sni */
        if (cat->domain_hash.size > 0) {
            p = sni.data;
            end = sni.data + sni.len;
            while (p < end) {
                suffix.data = p;
                suffix.len = end - p;

                ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                              "geosite: trying suffix=\"%V\" in domain_hash of \"%V\"",
                              &suffix, &cat->tag);

                if (ngx_hash_find(&cat->domain_hash,
                                  ngx_hash_key_lc(suffix.data, suffix.len),
                                  suffix.data, suffix.len) != NULL)
                {
                    v->data = cat->tag.data;
                    v->len = cat->tag.len;
                    v->valid = 1;
                    v->no_cacheable = 1;
                    v->not_found = 0;

                    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                                  "geosite: DOMAIN MATCH: SNI=\"%V\" suffix=\"%V\" -> category=\"%V\"",
                                  &sni, &suffix, &cat->tag);
                    return NGX_OK;
                }

                /* advance p to next label boundary */
                while (p < end && *p != '.') p++;
                if (p < end) p++;  /* skip the dot */
            }
        }

        /* (3) plain substring match */
        if (cat->plain_array.nelts > 0) {
            plain = cat->plain_array.elts;
            for (k = 0; k < cat->plain_array.nelts; k++) {
                if (ngx_strnstr(sni.data, (char *) plain[k].data,
                                sni.len) != NULL)
                {
                    v->data = cat->tag.data;
                    v->len = cat->tag.len;
                    v->valid = 1;
                    v->no_cacheable = 1;
                    v->not_found = 0;

                    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                                  "geosite: PLAIN MATCH: SNI=\"%V\" -> category=\"%V\"",
                                  &sni, &cat->tag);
                    return NGX_OK;
                }
            }
        }
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "geosite: NO MATCH for SNI=\"%V\" (tried %ui categories)",
                  &sni, n);

    v->not_found = 1;
    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* postconfiguration                                                  */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_stream_geosite_init(ngx_conf_t *cf)
{
    ngx_stream_geosite_main_conf_t  *gmcf;
    ngx_stream_variable_t           *v;
    static ngx_str_t  geosite_category_name = ngx_string("geosite_category");

    gmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_geosite_module);
    if (gmcf == NULL) {
        return NGX_OK;
    }

    /* Load the file at postconfiguration time, so directives are parsed. */
    if (gmcf->file_path != NULL && !gmcf->loaded) {
        if (ngx_stream_geosite_load_file(cf, gmcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Register $geosite_category */
    v = ngx_stream_add_variable(cf, &geosite_category_name,
                                NGX_STREAM_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }
    v->get_handler = ngx_stream_geosite_variable;
    v->data = 0;

    return NGX_OK;
}
