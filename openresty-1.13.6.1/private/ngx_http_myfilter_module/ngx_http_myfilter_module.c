#include <ngx_config.h>  
#include <ngx_core.h>  
#include <ngx_http.h>  
  
 // 配置项结构体  
typedef struct {  
    ngx_flag_t enable;  
} ngx_http_myfilter_conf_t;  
  
// 上下文结构体  
typedef struct {  
    ngx_int_t add_prefix;  
} ngx_http_myfilter_ctx_t;  
  
ngx_module_t ngx_http_myfilter_module;  // 前向声明  
  
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;  
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;  
  
// 需要添加的前缀内容  
static ngx_str_t filter_prefix = ngx_string("~~~~~~~This is a prefix~~~~~~~\n");  
  
static ngx_int_t ngx_http_myfilter_header_filter(ngx_http_request_t *r)  
{  
    ngx_http_myfilter_ctx_t  *ctx;  
    ngx_http_myfilter_conf_t *conf;  
  
    if (r->headers_out.status != NGX_HTTP_OK)  
        return ngx_http_next_header_filter(r);  // 交由下一个过滤模块处理  
  
    ctx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);  
    if (ctx)  
        return ngx_http_next_header_filter(r);  // 上下文已存在，不再处理  
  
    conf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);   // 获取配置项结构体  
    if (conf->enable == 0)  
        return ngx_http_next_header_filter(r);  // 此过滤模块未打开  
  
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_myfilter_ctx_t)); // 创建上下文结构体  
    if (ctx == NULL)  
        return NGX_ERROR;  
  
    ctx->add_prefix = 0; // 0表示不需要添加前缀  
    ngx_http_set_ctx(r, ctx, ngx_http_myfilter_module);  
  
    // 只处理Content-Type为text/plain类型的HTTP请求  
    if (r->headers_out.content_type.len >= sizeof("text/plain")-1 &&  
        ngx_strncasecmp(r->headers_out.content_type.data, (u_char *)"text/plain", sizeof("text/plain")-1) == 0)  
    {  
            ctx->add_prefix = 1; // 1表示需要加入前缀  
            if (r->headers_out.content_length_n > 0)  
                r->headers_out.content_length_n += filter_prefix.len;    // 响应包体长度增加  
    }  
  
    return ngx_http_next_header_filter(r);  
}  
  
static ngx_int_t ngx_http_myfilter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)  
{  
    ngx_http_myfilter_ctx_t  *ctx;  
  
    ctx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module); // 获取上下文结构体  
    if (ctx == NULL || ctx->add_prefix != 1)  
        return ngx_http_next_body_filter(r, in);    // 不添加前缀  
  
    ctx->add_prefix = 2; // 2表示已添加前缀  
  
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, filter_prefix.len);  
    b->start = b->pos = filter_prefix.data;  
    b->last = b->pos + filter_prefix.len;  
  
    // 链入待发送包体头部  
    ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);  
    cl->buf = b;  
    cl->next = in;  
  
    return ngx_http_next_body_filter(r, cl);    // 跳到下一个过滤模块  
}  
  
// 初始化HTTP过滤模块  
static ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf)  
{  
    ngx_http_next_header_filter = ngx_http_top_header_filter;     
    ngx_http_top_header_filter = ngx_http_myfilter_header_filter;  
  
    ngx_http_next_body_filter = ngx_http_top_body_filter;  
    ngx_http_top_body_filter = ngx_http_myfilter_body_filter;  
  
    return NGX_OK;  
}  
  
// 创建存储配置项的结构体  
static void* ngx_http_myfilter_create_conf(ngx_conf_t *cf)  
{  
    ngx_http_myfilter_conf_t *mycf;  
  
    mycf = (ngx_http_myfilter_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_myfilter_conf_t));  
    if (mycf == NULL)  
        return NULL;  
  
    mycf->enable = NGX_CONF_UNSET;  
    return mycf;  
}  
  
// 合并配置项  
static char* ngx_http_myfilter_merge_conf(ngx_conf_t *cf, void *parent, void *child)  
{  
    ngx_http_myfilter_conf_t *prev = (ngx_http_myfilter_conf_t *)parent;  
    ngx_http_myfilter_conf_t *conf = (ngx_http_myfilter_conf_t *)child;  
  
    ngx_conf_merge_value(conf->enable, prev->enable, 0);  // 合并函数  
  
    return NGX_CONF_OK;  
}  
  
static ngx_command_t ngx_http_myfilter_commands[] = {  
    {  
        ngx_string("myfilter"),  
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_FLAG,  
        ngx_conf_set_flag_slot,  
        NGX_HTTP_LOC_CONF_OFFSET,  
        offsetof(ngx_http_myfilter_conf_t, enable),  
        NULL,  
    },  
    ngx_null_command  
};  
   
  
// HTTP框架初始化时调用的八个函数  
static ngx_http_module_t ngx_http_myfilter_module_ctx = {  
    NULL,  
    ngx_http_myfilter_init,  
    NULL,  
    NULL,  
    NULL,  
    NULL,  
    ngx_http_myfilter_create_conf,  
    ngx_http_myfilter_merge_conf,  
};  
   
// 定义一个HTTP模块  
ngx_module_t ngx_http_myfilter_module = {  
    NGX_MODULE_V1,  // 0,0,0,0,0,0,1  
    &ngx_http_myfilter_module_ctx,  
    ngx_http_myfilter_commands,  
    NGX_HTTP_MODULE,  
    NULL,  
    NULL,  
    NULL,  
    NULL,  
    NULL,  
    NULL,  
    NULL,  
    NGX_MODULE_V1_PADDING,  // 0,0,0,0,0,0,0,0,保留字段  
};  

