#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pri_test.h>
#include <moon_db.h>
#include "cJSON.h"

typedef struct {
    ngx_str_t output_words;
    ngx_uint_t flag;
} ngx_http_hello_world_loc_conf_t;

// To process HelloWorld command arguments
static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

// Allocate memory for HelloWorld command
static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf);

// Copy HelloWorld argument to another place
static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

// Structure for the HelloWorld command
static ngx_command_t ngx_http_hello_world_commands[] = {
    {
        ngx_string("hello_world"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_hello_world, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, output_words),
        NULL
    },

    {
        ngx_string("test_flag"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, flag),
        NULL
    },
    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_hello_world_create_loc_conf,
    ngx_http_hello_world_merge_loc_conf
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_hello_world_module = {
    NGX_MODULE_V1,
    &ngx_http_hello_world_module_ctx,
    ngx_http_hello_world_commands,
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
            ngx_http_hello_world_module);

#if 0
    ngx_str_t output_format = ngx_string("hello world");

    int bodylen = output_format.len;
    r->headers_out.content_length_n = bodylen;
#endif
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
            ngx_http_hello_world_module);
    pr->headers_out.status = r->headers_out.status;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                "%s: %d",__FUNCTION__, r->headers_out.status); 

    if (r->headers_out.status == NGX_HTTP_OK)
    {
        int flag = 0;
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

static void ngx_http_hello_world_client_body_handler_pt(ngx_http_request_t *r)
{
    ngx_int_t rc = NGX_OK;
    ngx_buf_t* b;
    ngx_chain_t out[2];
    char log_buf[32] = {0};
    u_char body_buf[256] = {0};
    ngx_buf_t *p_body_buf = NULL;
    cJSON *root = NULL;
    cJSON *name = NULL;
    char json_buf[256] = {0};
    int db_ret = 0;

    ngx_http_hello_world_loc_conf_t* hlcf = NULL;
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);
    if (NULL == hlcf)
    {
    }

    show_str(log_buf, 32);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    p_body_buf = r->request_body->bufs->buf;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "length:%d", ngx_buf_size(p_body_buf));
    
    ngx_snprintf(body_buf, sizeof(body_buf), "%*s",
            ngx_buf_size(p_body_buf), p_body_buf->pos);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "main: receive body:%s", body_buf);

    test_mysql(1, 2, r->connection->log);

    root = cJSON_Parse((char *)body_buf);
    if (NULL == root)
    {
        return;
    }
    name = cJSON_GetObjectItemCaseSensitive(root, "name");
    if (NULL == name)
    {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "name: %s", name->valuestring);

    
    ngx_http_extern_request_mysql_ctx_t *my_ctx = ngx_http_get_module_ctx(r,
            ngx_http_hello_world_module);
    if (NULL == my_ctx)
    {
        my_ctx = ngx_palloc(r->pool, sizeof(ngx_http_extern_request_mysql_ctx_t));
        if (NULL == my_ctx)
        {
            return;
        }

        ngx_http_set_ctx(r, my_ctx, ngx_http_hello_world_module);
    }

    ngx_http_post_subrequest_t *my_sub_req = ngx_palloc(r->pool,
            sizeof(ngx_http_post_subrequest_t));
    if (NULL == my_sub_req)
    {
        return;
    }

    my_sub_req->handler = extern_db_sub_req_post_handler;

    my_sub_req->data = my_ctx;

    ngx_str_t sub_prefix = ngx_string("/mysql_query?name=hello");
    ngx_str_t sub_location;
    sub_location.len =sub_prefix.len;
    sub_location.data = ngx_palloc(r->pool,sub_location.len);
    ngx_snprintf(sub_location.data, sub_location.len, "%V",
           &sub_prefix);

    ngx_http_request_t *sr = NULL;
    rc = ngx_http_subrequest(r, &sub_location, NULL,
            &sr, my_sub_req, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK)
    {
        return;
    }

    return;
    moon_account_t account;

    memset(&account, 0, sizeof(account));
    snprintf(account.name, sizeof(account.name), "%s", name->valuestring);
    db_ret = moon_db_init_internal(r->connection->log);
    if (0 != db_ret)
    {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "000");

    db_ret = moon_db_account_query(r->connection->log, "my_ngx",
            &account);
    if (0 != db_ret && MOON_DB_NO_LINE != db_ret)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "db query failed: %d", db_ret);
        return;
    }

    if (MOON_DB_NO_LINE == db_ret)
    {
        account.reg_ts = time(NULL);
        db_ret = moon_db_account_add(r->connection->log, "my_ngx",
                &account);
        if (0 != db_ret)
        {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                    "%s: db ret: %d", __FUNCTION__, db_ret);
            return;
        }
    }

#if 1
//JSON response
            root = cJSON_CreateObject();
            cJSON_AddItemToObject(root, "res-info",
                    cJSON_CreateString("account_info"));

            cJSON_AddItemToObject(root, "name",
                    cJSON_CreateString(account.name));

            cJSON_AddItemToObject(root, "reg_timestamp",
                    cJSON_CreateNumber(account.reg_ts));

            cJSON_AddItemToObject(root, "last_login_timestamp",
                    cJSON_CreateNumber(account.last_login_ts));

            account.last_login_ts = time(NULL);
            db_ret = moon_db_account_update(r->connection->log, "my_ngx",
                    &account);
            if (0 != db_ret)
            {
                return;
            }

            r->headers_out.content_type.len = sizeof("application/json; charset=utf-8") - 1;
            r->headers_out.content_type.data = (u_char*)"application/json; charset=utf-8";
        
            b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        
            //
            show_str(log_buf, 32);
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                  "%s", log_buf);
        
            out[0].buf = b;
            out[0].next = NULL;

            snprintf(json_buf, sizeof(json_buf), "%s", cJSON_Print(root));
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                    "%s,length:%d", json_buf, strlen(json_buf));
            b->pos = (u_char*)cJSON_Print(root);
            b->last = b->pos + strlen(json_buf);
        
            b->memory = 1;
            b->last_buf = 1;
        
            //b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        
            //out[1].buf = b;
            //out[1].next = NULL;
        
            //b->pos = hlcf->output_words.data;
            //b->last = hlcf->output_words.data + (hlcf->output_words.len);
            //b->memory = 1;
            //b->last_buf = 1;

            
        
            r->headers_out.status = NGX_HTTP_OK;
            r->headers_out.content_length_n = strlen(json_buf);
            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
                return ;
            }
        
            rc = ngx_http_output_filter(r, &out[0]);
            ngx_http_finalize_request(r,rc);

            cJSON_Delete(root);
    
            return;
#else
        r->headers_out.content_type.len = sizeof("text/plain") - 1;
        r->headers_out.content_type.data = (u_char*)"text/plain";
    
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    
        //
        show_str(log_buf, 32);
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "%s", log_buf);
    
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "uri:%V, args: %V", &r->uri,
                              &r->args);
    
        out[0].buf = b;
        out[0].next = &out[1];
    
        if (1 == hlcf->flag)
        {
            b->pos = (u_char*)"hello_world1, ";
            b->last = b->pos + sizeof("hello_world1, ") - 1;
        }
        else
        {
            b->pos = (u_char*)"hello_world2, ";
            b->last = b->pos + sizeof("hello_world2, ") - 1;
        }
    
        b->memory = 1;
    
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    
        out[1].buf = b;
        out[1].next = NULL;
    
        b->pos = hlcf->output_words.data;
        b->last = hlcf->output_words.data + (hlcf->output_words.len);
        b->memory = 1;
        b->last_buf = 1;
    
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = hlcf->output_words.len + sizeof("hello_world1, ") - 1;
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return ;
        }
    
        rc = ngx_http_output_filter(r, &out[0]);
        ngx_http_finalize_request(r,rc);

        return;
#endif
}
#if 1

int ngx_response_info(ngx_http_request_t* r)
{
    ngx_int_t rc = NGX_OK;
    ngx_buf_t* b = NULL;
    ngx_chain_t out[2];
    char log_buf[32] = {0};
    cJSON *root = NULL;
    char json_buf[256] = {0};

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "res-info",
    cJSON_CreateString("no account info in body"));

    r->headers_out.content_type.len = sizeof("application/json; charset=utf-8") - 1;
    r->headers_out.content_type.data = (u_char*)"application/json; charset=utf-8";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    //
    show_str(log_buf, 32);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    out[0].buf = b;
    out[0].next = NULL;

    snprintf(json_buf, sizeof(json_buf), "%s", cJSON_Print(root));
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "%s,length:%d", json_buf, strlen(json_buf));
    b->pos = (u_char*)cJSON_Print(root);
    b->last = b->pos + strlen(json_buf);

    b->memory = 1;
    b->last_buf = 1;

    //b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    //out[1].buf = b;
    //out[1].next = NULL;

    //b->pos = hlcf->output_words.data;
    //b->last = hlcf->output_words.data + (hlcf->output_words.len);
    //b->memory = 1;
    //b->last_buf = 1;

            
        
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

static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t* r) {
    ngx_int_t rc = NGX_OK;
    int no_content_flag = 0;
    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                             //"test:%V", &r->headers_in.content_length->value);

    if (r->headers_in.content_length)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                                  "before: content length is %d",
                                  ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));
    }
    else
    {
        no_content_flag = 1;
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "no content");
    }

#if 1
    //return NGX_ERROR;
    if (0 == no_content_flag && ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len) <= 0)
    {
       ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "in: content length is %d",
                              ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));
        no_content_flag = 1;
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "no content");
    }
#endif

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "no content flag:%d", no_content_flag);
    if (no_content_flag)
    {
        return ngx_response_info(r);
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "after content length:%d", ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));

    rc = ngx_http_read_client_request_body(r,
            ngx_http_hello_world_client_body_handler_pt);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", "unknown respone");
        return rc;
    }

    return NGX_DONE;

#if 0
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char*)"text/plain";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    //
    show_str(log_buf, 32);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "uri:%V, args: %V", &r->uri,
                          &r->args);

    out[0].buf = b;
    out[0].next = &out[1];

    if (1 == hlcf->flag)
    {
        b->pos = (u_char*)"hello_world1, ";
        b->last = b->pos + sizeof("hello_world1, ") - 1;
    }
    else
    {
        b->pos = (u_char*)"hello_world2, ";
        b->last = b->pos + sizeof("hello_world2, ") - 1;
    }

    b->memory = 1;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[1].buf = b;
    out[1].next = NULL;

    b->pos = hlcf->output_words.data;
    b->last = hlcf->output_words.data + (hlcf->output_words.len);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = hlcf->output_words.len + sizeof("hello_world1, ") - 1;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out[0]);
#endif
}

#else

static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t* r) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    u_char *file_name = (u_char*)"/tmp/sgy.test";
    b->in_file = 1;
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    b->file->fd = ngx_open_file(file_name, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
        NGX_FILE_OPEN, 0);
    b->file->log = r->connection->log;
    b->file->name.data = file_name;
    b->file->name.len = strlen((const char *)file_name);
    if (b->file->fd <= 0)
    {
        return NGX_HTTP_NOT_FOUND;
    }
    if (ngx_file_info(file_name, &b->file->info) == NGX_FILE_ERROR)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_length_n = b->file->info.st_size;
    b->file_pos = 0;
    b->file_last = b->file->info.st_size;

    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));  
    if (cln == NULL)  
        return NGX_ERROR;

    cln->handler = ngx_pool_cleanup_file;
    ngx_pool_cleanup_file_t *clnf = cln->data;
    clnf->fd = b->file->fd;
    clnf->name = b->file->name.data;
    clnf->log = r->pool->log;

    ngx_str_t type = ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = type;
    
#if 1
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
#endif
    out.buf = b;  
    out.next = NULL; 

    return ngx_http_output_filter(r, &out);
}
#endif

static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_hello_world_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_world_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;
    conf->output_words.data = NULL;

    conf->flag = NGX_CONF_UNSET;

    return conf;
}

static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_hello_world_loc_conf_t* prev = parent;
    ngx_http_hello_world_loc_conf_t* conf = child;
    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "Nginx");
    ngx_conf_merge_uint_value(conf->flag, prev->flag,
            1);
    return NGX_CONF_OK;
}


static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

