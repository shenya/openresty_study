
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
 
typedef struct {
    ngx_uint_t test_conf_var;
    
} ngx_http_config_test_loc_conf_t;
 
static char* ngx_http_config_test(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
 
static void* ngx_http_config_test_create_loc_conf(ngx_conf_t* cf);
 
static char* ngx_http_config_test_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static void* ngx_http_config_test_create_main_conf(ngx_conf_t* cf);

static void* ngx_http_config_test_create_srv_conf(ngx_conf_t* cf);

static char* ngx_http_config_test_merge_srv_conf(ngx_conf_t* cf, void* parent, void* child);

static ngx_command_t ngx_http_config_test_commands[] = 
{
    {
	ngx_string("config_test"), 
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_config_test, 
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("test_conf_var"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_config_test_loc_conf_t, test_conf_var),
        NULL
    },

    ngx_null_command
};
 
static ngx_http_module_t ngx_http_config_test_module_ctx = 
{
    NULL,
    NULL,
    ngx_http_config_test_create_main_conf,
    NULL,
    ngx_http_config_test_create_srv_conf,
    NULL,//ngx_http_config_test_merge_srv_conf,
    ngx_http_config_test_create_loc_conf,
    ngx_http_config_test_merge_loc_conf
};
 
ngx_module_t ngx_http_config_test_module = {
    NGX_MODULE_V1,
    &ngx_http_config_test_module_ctx,
    ngx_http_config_test_commands,
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
 
static ngx_int_t ngx_http_config_test_handler(ngx_http_request_t* r)
    
{
    ngx_http_config_test_loc_conf_t  *clcf = NULL;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
 
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_config_test_module);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s: clcf test var: %d", __FUNCTION__,
                          clcf->test_conf_var);
    char buf[1024] = {0};
    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response_format = ngx_string("test_conf_var:%d");    

    ngx_snprintf(buf, sizeof(buf), (char *)response_format.data, clcf->test_conf_var);

    int data_len = strlen(buf);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = data_len;
    r->headers_out.content_type = type;

 
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
 
    ngx_buf_t *b = NULL;
    b = ngx_create_temp_buf(r->pool, data_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
 
    ngx_memcpy(b->pos, buf, data_len);
    b->last = b->pos + data_len;
    b->last_buf = 1;
 
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
 
    return ngx_http_output_filter(r, &out);
}

static void* ngx_http_config_test_create_main_conf(ngx_conf_t* cf) {
    ngx_http_config_test_loc_conf_t* conf;

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s:", __FUNCTION__);

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_config_test_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->test_conf_var = NGX_CONF_UNSET;
 
    return conf;
}

static void* ngx_http_config_test_create_srv_conf(ngx_conf_t* cf) {
    ngx_http_config_test_loc_conf_t* conf;

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s:", __FUNCTION__);
 
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_config_test_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->test_conf_var = NGX_CONF_UNSET;
 
    return conf;
}

static char* ngx_http_config_test_merge_srv_conf(ngx_conf_t* cf, void* parent, void* child) 
{
    ngx_http_config_test_loc_conf_t* prev = parent;
    ngx_http_config_test_loc_conf_t* conf = child;

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s: conf teset_var:%d, prev var: %d", __FUNCTION__,
                          conf->test_conf_var, prev->test_conf_var);

    ngx_conf_merge_uint_value(conf->test_conf_var, prev->test_conf_var, 1);

    return NGX_CONF_OK;
}

static void* ngx_http_config_test_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_config_test_loc_conf_t* conf;

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s:", __FUNCTION__);
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_config_test_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->test_conf_var = NGX_CONF_UNSET;
 
    return conf;
}
 
static char* ngx_http_config_test_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) 
{
    ngx_http_config_test_loc_conf_t* prev = parent;
    ngx_http_config_test_loc_conf_t* conf = child;

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s: conf teset_var:%d, prev var: %d", __FUNCTION__,
                          conf->test_conf_var, prev->test_conf_var);

    ngx_conf_merge_uint_value(conf->test_conf_var, prev->test_conf_var, 1);

    return NGX_CONF_OK;
}

static char* ngx_http_config_test(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) 
{
	ngx_http_core_loc_conf_t* clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_config_test_handler;
    return NGX_CONF_OK;
}
