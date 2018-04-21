#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pri_test.h>
//#include <moon_db.h>
//#include "cJSON.h"

typedef struct {
    ngx_str_t stock[6];
} ngx_http_extern_request_ctx_t;

static char* ngx_http_extern_request(ngx_conf_t* cf,
        ngx_command_t* cmd, void* conf);

// Structure for the HelloWorld command
static ngx_command_t ngx_http_extern_request_commands[] = {
    {
        ngx_string("extern_request"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_extern_request, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_extern_request_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_extern_request_module = {
    NGX_MODULE_V1,
    &ngx_http_extern_request_module_ctx,
    ngx_http_extern_request_commands,
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

static void extern_request_post_handler(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK)
    {
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }

    ngx_http_extern_request_ctx_t *my_ctx = ngx_http_get_module_ctx(r,
            ngx_http_extern_request_module);
    ngx_str_t output_format = ngx_string("stock[%V], Today current price: %V,"\
            "volumn: %V");

    int bodylen = output_format.len + my_ctx->stock[0].len + my_ctx->stock[1].len +
            my_ctx->stock[4].len - 6;
    r->headers_out.content_length_n = bodylen;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool,bodylen);
    ngx_snprintf(b->pos, bodylen, (char *)output_format.data,
            &my_ctx->stock[0], &my_ctx->stock[1], &my_ctx->stock[4]);
    b->last = b->pos + bodylen;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    static ngx_str_t type = ngx_string("text/plain; charset=GBK");
    r->headers_out.content_type= type;
    r->headers_out.status =NGX_HTTP_OK;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r,&out);

    ngx_http_finalize_request(r,ret);
}

static ngx_int_t extern_request_sub_req_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc)
{
    ngx_str_t response_data;
    ngx_http_request_t *pr = r->parent;

    ngx_http_extern_request_ctx_t *my_ctx = ngx_http_get_module_ctx(pr,
            ngx_http_extern_request_module);
    pr->headers_out.status = r->headers_out.status;

    if (r->headers_out.status == NGX_HTTP_OK)
    {
        int flag = 0;

        ngx_buf_t *sub_recv_buf = &r->upstream->buffer;

        response_data.data = sub_recv_buf->pos;
        response_data.len = ngx_buf_size(sub_recv_buf);
        //response_data.len -= 20;

        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                    "data: %d, %V", response_data.len,
                                    &response_data);

        for (; sub_recv_buf->pos != sub_recv_buf->last; sub_recv_buf->pos++)
        {
            if (*sub_recv_buf->pos == ',' || *sub_recv_buf->pos == '\"')
            {
                if (flag > 0)
                {
                    my_ctx->stock[flag - 1].len = sub_recv_buf->pos -
                            my_ctx->stock[flag - 1].data;
                }

                flag++;
                my_ctx->stock[flag -1].data = sub_recv_buf->pos + 1;

                if (flag > 6)
                {
                   break;
                }
            }
        }
    }

    pr->write_event_handler = extern_request_post_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_extern_request_handler(ngx_http_request_t* r) {
    ngx_int_t rc = NGX_OK;

    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              //"%s", "content length is 20171118");

    ngx_http_extern_request_ctx_t *my_ctx = ngx_http_get_module_ctx(r,
            ngx_http_extern_request_module);
    if (NULL == my_ctx)
    {
        my_ctx = ngx_palloc(r->pool, sizeof(ngx_http_extern_request_ctx_t));
        if (NULL == my_ctx)
        {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, my_ctx, ngx_http_extern_request_module);
    }

    ngx_http_post_subrequest_t *my_sub_req = ngx_palloc(r->pool,
            sizeof(ngx_http_post_subrequest_t));
    if (NULL == my_sub_req)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    my_sub_req->handler = extern_request_sub_req_post_handler;

    my_sub_req->data = my_ctx;

    ngx_str_t sub_prefix = ngx_string("/list=");
    ngx_str_t sub_location;
    sub_location.len =sub_prefix.len + r->args.len;
    sub_location.data = ngx_palloc(r->pool,sub_location.len);
    ngx_snprintf(sub_location.data, sub_location.len, "%V%V",
           &sub_prefix, &r->args);

    ngx_http_request_t *sr = NULL;
    rc = ngx_http_subrequest(r, &sub_location, NULL,
            &sr, my_sub_req, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DONE;
}

static char* ngx_http_extern_request(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_extern_request_handler;
    return NGX_CONF_OK;
}

