#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*上下文结构体*/
typedef struct
{
    ngx_http_status_t status;
    ngx_str_t backendServer;
}ngx_http_mytest_ctx_t;

/*uptream相关配置，例如超时等待时间等*/
typedef struct
{
    ngx_http_upstream_conf_t upstream;
} ngx_http_mytest_conf_t;


/*配置项处理函数*/
static char *
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/*真正的处理函数*/
/*设置upstream的host、回调函数、启动upstream等*/
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);


/*创建ngx_http_mytest_conf_t结构体，硬编码参数*/
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);


/*设置hide_headers_hash*/
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


/*解析http头部*/
static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r);


/*处理http响应行*/
static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r);


/*安全考虑隐藏头部*/
static ngx_str_t  ngx_http_proxy_hide_headers[] =
{
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


/*command 结构体数组*/
static ngx_command_t  ngx_http_mytest_commands[] =
{

    {
        ngx_string("mytest"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
        ngx_http_mytest,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};


/*模块上下文*/
static ngx_http_module_t  ngx_http_mytest_module_ctx =
{
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_mytest_create_loc_conf,/* create location configuration */
    ngx_http_mytest_merge_loc_conf  /* merge location configuration */
};


/*nginx 模块*/
ngx_module_t  ngx_http_mytest_module =
{
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,           /* module context */
    ngx_http_mytest_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void*
ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mytest_conf_t *mycf;

    mycf = (ngx_http_mytest_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }

    /*对结构体变量中的成员进行硬编码，超时连接相关*/
    mycf->upstream.connect_timeout = 60000;
    mycf->upstream.send_timeout = 60000;
    mycf->upstream.read_timeout = 60000;
    mycf->upstream.store_access = 0600;

    /*处理上游服务器包体方式相关，这里以固定buffer转发包体*/
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;
    mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;


    /*upstream模块要求hide_headers必须初始化*/
    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    return mycf;
}


static char *
ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t *)parent;
    ngx_http_mytest_conf_t *conf = (ngx_http_mytest_conf_t *)child;

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    /*hide header*/
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
     &prev->upstream, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/*upstream  create_request 回调，构建到上游服务器的请求*/
static ngx_int_t
mytest_upstream_create_request(ngx_http_request_t *r)
{
    /*模仿baidu搜索请求 /s?wd= */
    static ngx_str_t backendQueryLine =
        ngx_string("GET /s?wd=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");

    /*请求长度 -2表示 %V*/
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;

    /*内存池申请内存，请求结束时内存被自动释放*/
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL)
        return NGX_ERROR;

    /*last要指向请求的末尾*/
    b->last = b->pos + queryLineLen;

    /*作用相当于snprintf*/
    ngx_snprintf(b->pos, queryLineLen ,(char*)backendQueryLine.data, &r->args);

    /*发送给上游服务器的请求*/
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL)
        return NGX_ERROR;

    /*request_bufs这里只包含1个ngx_buf_t缓冲区*/
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    /*header_hash不可以为0*/
    r->header_hash = 1;
    return NGX_OK;
}



static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    /*取出http请求的上下文*/
    ngx_http_mytest_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (ctx == NULL)
    {
        return NGX_ERROR;
    }

    u = r->upstream;

    /*解析http响应行*/
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    /*NGX_AGAIN表示继续解析*/
    if (rc == NGX_AGAIN)
    {
        return rc;
    }

    /*NGX_ERROR没有接收到合法的http响应行*/
    if (rc == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    /*解析到完整到响应行，将解析出来的内容赋值到headers_in结构体中*/
    if (u->state)
    {
        u->state->status = ctx->status.code;
    }

    /*赋值操作*/
    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;

    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL)
    {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len); 


    /*开始解析http响应头部*/
    /*之后收到的新字符流将有新的回调函数解析*/
    u->process_header = mytest_upstream_process_header;

    /*如果本次收到的字符流除了http响应行外，还有多余的字符*/
    /*将由mytest_upstream_process_header方法解析*/
    return mytest_upstream_process_header(r);
}


/*处理http头部*/
static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc;

    /*为http头部量身定制*/
    /*例如 key 存储"Content-Length"*/
    /*value 存储 "1024" */
    ngx_table_elt_t *h;

    ngx_http_upstream_header_t     *hh;

    ngx_http_upstream_main_conf_t  *umcf;

    /*将upstream模块配置项ngx_http_upstream_main_conf_t取了*/
    /*该结构体中存储了需要做统一处理的http头部名称和回调方法*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    /*循环的解析所有的http头部*/
    for ( ;; )
    {
    /*解析http头部*/
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        /*NGX_OK解析出一行http头部*/
        if (rc == NGX_OK)
        {
            /*向headers_in.headers这个ngx_list_t链表中添加http头部*/
        /*ngx_list_t是先插入再赋值*/
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL)
            {
                return NGX_ERROR;
            }

            /*构造刚刚添加到headers链表中的http头部*/
            h->hash = r->header_hash;

        /*key-头部名称 value-对应的值*/
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;


        /*zx:作者这里分配这么大空间的原因在于，在结构体中有三个变量*/
        //1.key
        //2.value
        //3.lowcase_case
        /*一次申请这一整段空间，+1用来'\0'来区分*/
        /*这也在于ngx_str_t的特性在于data字段记录的只是字串地址*/
            h->key.data = ngx_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL)
            {
                return NGX_ERROR;
            }

        /*赋值操作*/
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index)
            {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }
            else
            {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            /*upstream模块会对一些http头部做特殊处理*/
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }

        /*返回NGX_HTTP_PARSE_HEADER_DONE表示响应中所有的http头部都解析*/
        if (rc == NGX_HTTP_PARSE_HEADER_DONE)
        {
            /*如果之前解析http头部时没有发现server和date头部*/
        /*据http协议添加这两个头部*/
            if (r->upstream->headers_in.server == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

        /*zx:查看ngx_hash_key_lc/ngx_hash_key源码可知，可以改写*/
        ngx_str_t str=ngx_string("server");
        h->hash=ngx_hash_key_lc(str.data,str.len);
#if 0
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                                      ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
#endif

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

        ngx_str_t str=ngx_string("date");
        /*zx:同上*/
        h->hash=ngx_hash_key_lc(str.data,str.len);
#if 0
                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
#endif

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

    /*没有解析到完整的http头部，继续接收新的字符流*/
        if (rc == NGX_AGAIN)
        {
            return NGX_AGAIN;
        }

        /*其他返回值都是非法的*/
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

/*finalize_request回调 请求结束前会调用*/
static void
mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "mytest_upstream_finalize_request");
}


static char *
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    /*首先找到mytest配置项所属的配置块，clcf貌似是location块内的数据*/
    /*结构，其实不然，它可以是main、srv或者loc级别配置项，也就是说在每个*/
    /*http{}和server{}内也都有一个ngx_http_core_loc_conf_t结构体*/
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    /*http框架在处理用户请求进行到NGX_HTTP_CONTENT_PHASE阶段时，如果*/
    /*请求的主机域名、URI与mytest配置项所在的配置块相匹配，就将调用我们*/
    /*实现的ngx_http_mytest_handler方法处理这个请求*/
    clcf->handler = ngx_http_mytest_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
    /*首先建立http上下文结构体ngx_http_mytest_ctx_t*/
    ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (myctx == NULL)
    {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL)
        {
            return NGX_ERROR;
        }
        /*将新建的上下文与请求关联起来*/
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
    }

    /*对每1个要使用upstream的请求，必须调用且只能调用1次*/
    /*ngx_http_upstream_create方法，它会初始化r->upstream成员*/
    if (ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    /*得到配置upstream结构体ngx_http_mytest_conf_t*/
    ngx_http_mytest_conf_t  *mycf = (ngx_http_mytest_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);

    /*配置upstream*/
    ngx_http_upstream_t *u = r->upstream;

    /*这里用配置文件中的结构体来赋给r->upstream->conf成员*/
    /*ngx_http_upstream_conf_t结构*/
    u->conf = &mycf->upstream;

    /*决定转发包体时使用的缓冲区*/
    u->buffering = mycf->upstream.buffering;

    /*以下代码开始初始化resolved结构体，用来保存上游服务器的地址*/

    u->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    /*这里的上游服务器就是www.baidu.com*/
    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*) "www.baidu.com");
    if (pHost == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gethostbyname fail. %s", strerror(errno));

        return NGX_ERROR;
    }

    /*访问上游服务器的80端口*/
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);

    memcpy(&backendSockAddr.sin_addr,pHost->h_addr_list[0],sizeof(struct in_addr));
    char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    /*inet_addr*/
    //backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    /*将地址设置到resolved成员中*/
    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    //add by sgy from web
    u->resolved->port = htons((in_port_t)80);

    /*设置三个必须实现的回调方法:创建请求、处理头部、请求销毁*/
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;

    /*这里必须将count成员加1*/
    r->main->count++;
    /*启动upstream*/
    ngx_http_upstream_init(r);
    /*必须返回NGX_DONE*/
    return NGX_DONE;
}
