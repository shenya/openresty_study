#include <ngx_config.h>  
#include <ngx_core.h>  
#include <ngx_http.h>  
  
typedef struct
{  
    ngx_http_upstream_conf_t upstream;
    ngx_int_t                  index;
    ngx_uint_t                 gzip_flag;
} ngx_http_upstream_oth_loc_conf_t;

typedef struct {
    size_t                     rest;
    ngx_http_request_t        *request;
} ngx_http_up_other_ctx_t;

typedef struct {
    int type;
    int length;
} up_other_msg_header_t;

static ngx_int_t ngx_http_upstream_oth_handler(ngx_http_request_t* r);
  
static void* ngx_http_upstream_oth_create_loc_conf(ngx_conf_t* cf);  
  
static char* ngx_http_upstream_oth_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);  

static char *
ngx_http_up_other_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_upstream_oth_commands[] =   
{
   {  
    ngx_string("uptream_oth_pass"),   
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,  
        ngx_http_up_other_pass,   
        NGX_HTTP_LOC_CONF_OFFSET,  
        0,  
        NULL  
    },
    ngx_null_command  
};

static ngx_http_module_t ngx_http_upstream_oth_module_ctx =
{
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL,
    ngx_http_upstream_oth_create_loc_conf,
    ngx_http_upstream_oth_merge_loc_conf
};  
  
ngx_module_t ngx_http_upstream_oth_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_oth_module_ctx,
    ngx_http_upstream_oth_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_up_other_create_request(ngx_http_request_t *r)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  

    cl->buf = b;
    cl->next = NULL;

    b->pos = (u_char*)"Hello World";
    b->last = b->pos + sizeof("Hello World") - 1;
    b->memory = 1;

    r->upstream->request_bufs = cl;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http up other request",);

    return NGX_OK;
}

static void
ngx_http_up_other_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http memcached request");
    return;
}

static void
ngx_http_up_other_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http up other request");
    return;
}

static ngx_int_t
ngx_http_up_other_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u = NULL;
    up_other_msg_header_t *msg_hdr = NULL;
    ngx_buf_t               *b = NULL;

    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "process header for up other");

    b = &u->buffer;

    if (ngx_buf_size(b) < sizeof(up_other_msg_header_t))
    {
        return NGX_AGAIN;
    }

    msg_hdr = (up_other_msg_header_t *)u->buffer.start;
    if (1 == msg_hdr->type)
    {
        r->headers_out.content_type.len = sizeof("application/json; charset=utf-8") - 1;
        r->headers_out.content_type.data = (u_char*)"application/json; charset=utf-8";
    }

    u->headers_in.content_length_n = msg_hdr->length;

    u->buffer.pos = u->buffer.pos + sizeof(up_other_msg_header_t);

    u->headers_in.status_n = 200;
    u->state->status = 200;

    return NGX_OK;
}

static ngx_int_t
ngx_http_up_other_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

static char *
ngx_http_up_other_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_oth_loc_conf_t *mlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_upstream_oth_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_up_other_filter_init(void *data)
{
    ngx_http_up_other_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n;
        ctx->rest = -1;
    } else {
        u->length = 0;
    }

    return NGX_OK;
}
static ngx_int_t
ngx_http_up_other_filter(void *data, ssize_t bytes)
{
    ngx_http_up_other_ctx_t  *ctx = data;

    u_char               *last;
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    ngx_log_error(NGX_LOG_EMERG, ctx->request->connection->log, 0,
        "%s: %O, rest: %z, bytes: %d", __FUNCTION__,
        u->length, ctx->rest, bytes);

    if (u->length == (ssize_t) ctx->rest) {
        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        ngx_log_error(NGX_LOG_EMERG, ctx->request->connection->log, 0,
            "%s:return ok %O, rest: %z, bytes: %d", __FUNCTION__,
            u->length, ctx->rest, bytes);

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "memcached filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);


    ctx->rest -= bytes;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_oth_handler(ngx_http_request_t* r)
{  
    ngx_int_t rc;  
    ngx_http_upstream_t            *u;
    ngx_http_upstream_oth_loc_conf_t* conf = NULL;  
    ngx_http_up_other_ctx_t *ctx = NULL;

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_upstream_create(r);
    if (NGX_OK != rc) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;   
    ngx_str_set(&u->schema, "upstream_other://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_upstream_oth_module;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_oth_module);
    if (NULL == conf)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "no conf",);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->conf = &conf->upstream;

    u->create_request = ngx_http_up_other_create_request;
    u->reinit_request = ngx_http_up_other_reinit_request;
    u->process_header = ngx_http_up_other_process_header;
    u->abort_request = ngx_http_up_other_abort_request;
    u->finalize_request = ngx_http_up_other_finalize_request;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_up_other_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_upstream_oth_module);

    u->input_filter_init = ngx_http_up_other_filter_init;
    u->input_filter = ngx_http_up_other_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static void* ngx_http_upstream_oth_create_loc_conf(ngx_conf_t* cf) {  
    ngx_http_upstream_oth_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_oth_loc_conf_t));  
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->upstream.connect_timeout = 60000;
    conf->upstream.send_timeout = 60000;
    conf->upstream.read_timeout = 60000;
    conf->upstream.store_access = 0600;

    conf->upstream.buffering = 0;
    conf->upstream.bufs.num = 8;
    conf->upstream.bufs.size = ngx_pagesize;
    conf->upstream.buffer_size = ngx_pagesize;
    conf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    conf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    return conf;  
}

static char* ngx_http_upstream_oth_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)   
{
    //ngx_http_upstream_oth_loc_conf_t* prev = parent;
    //ngx_http_upstream_oth_loc_conf_t* conf = child;
    return NGX_CONF_OK;
}
