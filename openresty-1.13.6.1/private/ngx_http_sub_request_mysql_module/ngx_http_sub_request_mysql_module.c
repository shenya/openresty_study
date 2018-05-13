#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cJSON.h"

typedef struct {
    ngx_str_t output_words;
    ngx_uint_t flag;
} ngx_http_sub_request_mysql_loc_conf_t;

static char* ngx_http_sub_request_mysql(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static void* ngx_http_sub_request_mysql_create_loc_conf(ngx_conf_t* cf);

static char* ngx_http_sub_request_mysql_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static ngx_command_t ngx_http_sub_request_mysql_commands[] = {
    {
        ngx_string("sub_request_mysql"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_sub_request_mysql, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_sub_request_mysql_loc_conf_t, output_words),
        NULL
    },

    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_sub_request_mysql_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_sub_request_mysql_create_loc_conf,
    ngx_http_sub_request_mysql_merge_loc_conf
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_sub_request_mysql_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_request_mysql_module_ctx,
    ngx_http_sub_request_mysql_commands,
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

typedef struct {
    ngx_str_t name;
    ngx_str_t db_request_data;
} ngx_http_extern_request_mysql_ctx_t;

static void extern_db_request_post_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                "%s: status[%d]",__FUNCTION__, r->headers_out.status); 

    if (r->headers_out.status != NGX_HTTP_OK)
    {
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }

    ngx_http_extern_request_mysql_ctx_t *my_ctx = ngx_http_get_module_ctx(r,
            ngx_http_sub_request_mysql_module);

    int bodylen = my_ctx->db_request_data.len;
    r->headers_out.content_length_n = bodylen;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool,bodylen);
    ngx_snprintf(b->pos, bodylen, (char *)my_ctx->db_request_data.data);
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
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "%s: send header ret[%d]", __FUNCTION__, ret);
    ret = ngx_http_output_filter(r,&out);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "%s: send body ret[%d]", __FUNCTION__, ret); 

    ngx_http_finalize_request(r,ret);
}

static ngx_int_t extern_db_sub_req_post_handler(ngx_http_request_t *r,
        void *data, ngx_int_t rc)
{
    ngx_str_t response_data;
    ngx_http_request_t *pr = r->parent;

    ngx_http_extern_request_mysql_ctx_t *my_ctx = ngx_http_get_module_ctx(pr,
            ngx_http_sub_request_mysql_module);
    pr->headers_out.status = r->headers_out.status;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                "%s: %d",__FUNCTION__, r->headers_out.status);

    if (r->headers_out.status == NGX_HTTP_OK)
    {
        ngx_buf_t *sub_recv_buf = &r->upstream->buffer;

        response_data.data = sub_recv_buf->pos;
        response_data.len = ngx_buf_size(sub_recv_buf);

        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "data: %d, %V", response_data.len,
                &response_data);
        my_ctx->db_request_data.len = response_data.len;
        my_ctx->db_request_data.data = response_data.data;
    }

    pr->write_event_handler = extern_db_request_post_handler;

    return NGX_OK;
}

static void ngx_http_sub_request_mysql_client_body_handler_pt(ngx_http_request_t *r)
{
    ngx_int_t rc = NGX_OK;
    char log_buf[32] = {0};
    u_char body_buf[256] = {0};
    ngx_buf_t *p_body_buf = NULL;
    cJSON *root = NULL;
    cJSON *name = NULL;
    cJSON *command = NULL;
    cJSON *age = NULL;

    ngx_http_sub_request_mysql_loc_conf_t* hlcf = NULL;
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_request_mysql_module);
    if (NULL == hlcf)
    {
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    p_body_buf = r->request_body->bufs->buf;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "length:%d", ngx_buf_size(p_body_buf));
    
    ngx_snprintf(body_buf, sizeof(body_buf), "%*s",
            ngx_buf_size(p_body_buf), p_body_buf->pos);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "main: receive body:%s", body_buf);

    root = cJSON_Parse((char *)body_buf);
    if (NULL == root)
    {
        return;
    }

    command = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (NULL == command)
    {
        return;
    }
    
    name = cJSON_GetObjectItemCaseSensitive(root, "name");
    if (NULL == name)
    {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "parse cmd: %s, name: %s",
                          command->valuestring,
                          name->valuestring);    

    ngx_http_extern_request_mysql_ctx_t *my_ctx = ngx_http_get_module_ctx(r,
            ngx_http_sub_request_mysql_module);
    if (NULL == my_ctx)
    {
        my_ctx = ngx_palloc(r->pool, sizeof(ngx_http_extern_request_mysql_ctx_t));
        if (NULL == my_ctx)
        {
            return;
        }

        ngx_http_set_ctx(r, my_ctx, ngx_http_sub_request_mysql_module);
    }

    ngx_http_post_subrequest_t *my_sub_req = ngx_palloc(r->pool,
            sizeof(ngx_http_post_subrequest_t));
    if (NULL == my_sub_req)
    {
        return;
    }

    my_sub_req->handler = extern_db_sub_req_post_handler;

    my_sub_req->data = my_ctx;

    ngx_str_t sub_uri;
    ngx_str_t sub_args;

    if (0 == ngx_strncmp(command->valuestring, "query", strlen("query")))
    {
        sub_uri.len = ngx_strlen("/mysql_query");
        sub_uri.data = ngx_palloc(r->pool,sub_uri.len);
        ngx_snprintf(sub_uri.data, sub_uri.len, "%s",
               "/mysql_query");

        sub_args.len = ngx_strlen("name=") + ngx_strlen(name->valuestring);
        sub_args.data = ngx_palloc(r->pool,sub_args.len);
        ngx_snprintf(sub_args.data, sub_args.len, "%s%s",
               "name=", name->valuestring);
    }
    else if (0 == ngx_strncmp(command->valuestring, "add", strlen("add")))
    {
        age = cJSON_GetObjectItemCaseSensitive(root, "age");
        if (NULL == age)
        {
            return;
        }
        sub_uri.len = ngx_strlen("/mysql_add");
        sub_uri.data = ngx_palloc(r->pool,sub_uri.len);
        ngx_snprintf(sub_uri.data, sub_uri.len, "%s",
               "/mysql_add");

        sub_args.len = ngx_strlen("name=") + ngx_strlen(name->valuestring)
                + ngx_strlen("age=") + ngx_strlen(age->valuestring) + 1;
        sub_args.data = ngx_palloc(r->pool,sub_args.len);
        ngx_snprintf(sub_args.data, sub_args.len, "%s%s&%s%s",
               "name=", name->valuestring, "age=", age->valuestring);
    }
    else if (0 == ngx_strncmp(command->valuestring, "delete", strlen("delete")))
    {
        sub_uri.len = ngx_strlen("/mysql_delete");
        sub_uri.data = ngx_palloc(r->pool,sub_uri.len);
        ngx_snprintf(sub_uri.data, sub_uri.len, "%s",
               "/mysql_delete");

        sub_args.len = ngx_strlen("name=") + ngx_strlen(name->valuestring);
        sub_args.data = ngx_palloc(r->pool,sub_args.len);
        ngx_snprintf(sub_args.data, sub_args.len, "%s%s",
               "name=", name->valuestring);
    }
    else if (0 == ngx_strncmp(command->valuestring, "update", strlen("update")))
    {
        age = cJSON_GetObjectItemCaseSensitive(root, "age");
        if (NULL == age)
        {
            return;
        }
        sub_uri.len = ngx_strlen("/mysql_update");
        sub_uri.data = ngx_palloc(r->pool,sub_uri.len);
        ngx_snprintf(sub_uri.data, sub_uri.len, "%s",
               "/mysql_update");

        sub_args.len = ngx_strlen("name=") + ngx_strlen(name->valuestring)
                + ngx_strlen("age=") + ngx_strlen(age->valuestring) + 1;
        sub_args.data = ngx_palloc(r->pool,sub_args.len);
        ngx_snprintf(sub_args.data, sub_args.len, "%s%s&%s%s",
               "name=", name->valuestring, "age=", age->valuestring);
    }
    else if (0 == ngx_strncmp(command->valuestring, "jquery", strlen("jquery")))
    {
        sub_uri.len = ngx_strlen("/redis_get");
        sub_uri.data = ngx_palloc(r->pool,sub_uri.len);
        ngx_snprintf(sub_uri.data, sub_uri.len, "%s",
                "/redis_get");

        sub_args.len = ngx_strlen("key=") + ngx_strlen(name->valuestring);
        sub_args.data = ngx_palloc(r->pool,sub_args.len);
        ngx_snprintf(sub_args.data, sub_args.len, "%s%s",
               "key=", name->valuestring);
    }
    else
    {

    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "sub request uri: %V, args: %V",
                          &sub_uri, &sub_args);

    ngx_http_request_t *sr = NULL;
    rc = ngx_http_subrequest(r, &sub_uri, &sub_args,
            &sr, my_sub_req, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK)
    {
        return;
    }

    return;
}

static int ngx_response_info(ngx_http_request_t* r)
{
    ngx_int_t rc = NGX_OK;
    ngx_buf_t* b = NULL;
    ngx_chain_t out[2];
    cJSON *root = NULL;
    char json_buf[256] = {0};

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "res-info",
    cJSON_CreateString("no account info in body"));

    r->headers_out.content_type.len = sizeof("application/json; charset=utf-8") - 1;
    r->headers_out.content_type.data = (u_char*)"application/json; charset=utf-8";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[0].buf = b;
    out[0].next = NULL;

    snprintf(json_buf, sizeof(json_buf), "%s", cJSON_Print(root));
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "%s,length:%d", json_buf, strlen(json_buf));
    b->pos = (u_char*)cJSON_Print(root);
    b->last = b->pos + strlen(json_buf);

    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = strlen(json_buf);
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    rc = ngx_http_output_filter(r, &out[0]);
    ngx_http_finalize_request(r,rc);

    cJSON_Delete(root);

    return rc;
}

static ngx_int_t ngx_http_sub_request_mysql_handler(ngx_http_request_t* r) {
    ngx_int_t rc = NGX_OK;
    int no_content_flag = 0;

    if (r->headers_in.content_length)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                  "%s: content length is %d", __FUNCTION__,
                                  ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));
    }
    else
    {
        no_content_flag = 1;
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "no content");
    }

    if (0 == no_content_flag && ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len) <= 0)
    {
       ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "in: content length is %d",
                              ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));
        no_content_flag = 1;
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "no content");
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "no content flag:%d", no_content_flag);
    if (no_content_flag)
    {
        return ngx_response_info(r);
    }

    rc = ngx_http_read_client_request_body(r,
            ngx_http_sub_request_mysql_client_body_handler_pt);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", "unknown respone");
        return rc;
    }

    return NGX_DONE;
}

static void* ngx_http_sub_request_mysql_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_sub_request_mysql_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_request_mysql_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;
    conf->output_words.data = NULL;

    conf->flag = NGX_CONF_UNSET;

    return conf;
}

static char* ngx_http_sub_request_mysql_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_sub_request_mysql_loc_conf_t* prev = parent;
    ngx_http_sub_request_mysql_loc_conf_t* conf = child;

    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "Nginx");
    ngx_conf_merge_uint_value(conf->flag, prev->flag,
            1);
    return NGX_CONF_OK;
}

static char* ngx_http_sub_request_mysql(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_sub_request_mysql_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);

    return NGX_CONF_OK;
}
