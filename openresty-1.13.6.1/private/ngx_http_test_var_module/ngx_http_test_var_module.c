#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pri_test.h>
#include <moon_db.h>
#include "cJSON.h"

typedef struct {
    int variable_index;
    ngx_str_t variable_name;
    ngx_str_t equal_value;
} ngx_http_test_var_loc_conf_t;

// To process HelloWorld command arguments
static char* ngx_http_test_var(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

// Allocate memory for HelloWorld command
static void* ngx_http_test_var_create_loc_conf(ngx_conf_t* cf);

static ngx_int_t
ngx_http_mytest_init(ngx_conf_t *cf);

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r);

// Structure for the HelloWorld command
static ngx_command_t ngx_http_test_var_commands[] = {
    {
        ngx_string("test_var"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_test_var, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_test_var_module_ctx = {
    NULL,
    ngx_http_mytest_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_test_var_create_loc_conf,
    NULL
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_test_var_module = {
    NGX_MODULE_V1,
    &ngx_http_test_var_module_ctx,
    ngx_http_test_var_commands,
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
ngx_http_mytest_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_mytest_handler;

    return NGX_OK;
}

static void* ngx_http_test_var_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_test_var_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_test_var_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->variable_index = NGX_CONF_UNSET;

    return conf;
}

static char* ngx_http_test_var(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_str_t *value;
    ngx_http_test_var_loc_conf_t *test_var_conf = conf;

    value =cf->args->elts;

    if (cf->args->nelts != 3)
    {
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] == '$')
    {
        value[1].data++;
        value[1].len--;

        test_var_conf->variable_index = ngx_http_get_variable_index(cf, &value[1]);
        if (test_var_conf->variable_index == NGX_ERROR)
        {
            return NGX_CONF_ERROR;
        }

        test_var_conf->variable_name = value[1];
    }
    else
    {
        return NGX_CONF_ERROR;
    }

    test_var_conf->equal_value =value[2];

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
    ngx_http_test_var_loc_conf_t *conf;
    ngx_http_variable_value_t*vv;

    conf =ngx_http_get_module_loc_conf(r, ngx_http_test_var_module);
    if (conf == NULL)
    {
        return NGX_ERROR;
    }

    if (conf->variable_index == -1)
    {
        return NGX_DECLINED;
    }

    vv = ngx_http_get_indexed_variable(r, conf->variable_index);
    if (vv == NULL || vv->not_found)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (vv->len == conf->equal_value.len &&
        0 == ngx_strncmp(conf->equal_value.data, vv->data, vv->len))
    {
       return NGX_DECLINED;
    }

    return NGX_HTTP_FORBIDDEN;
}

