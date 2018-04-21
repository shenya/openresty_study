#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*�����Ľṹ��*/
typedef struct
{
    ngx_http_status_t status;
    ngx_str_t backendServer;
}ngx_http_mytest_ctx_t;

/*uptream������ã����糬ʱ�ȴ�ʱ���*/
typedef struct
{
    ngx_http_upstream_conf_t upstream;
} ngx_http_mytest_conf_t;


/*�����������*/
static char *
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/*�����Ĵ�������*/
/*����upstream��host���ص�����������upstream��*/
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);


/*����ngx_http_mytest_conf_t�ṹ�壬Ӳ�������*/
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);


/*����hide_headers_hash*/
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


/*����httpͷ��*/
static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r);


/*����http��Ӧ��*/
static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r);


/*��ȫ��������ͷ��*/
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


/*command �ṹ������*/
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


/*ģ��������*/
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


/*nginx ģ��*/
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

    /*�Խṹ������еĳ�Ա����Ӳ���룬��ʱ�������*/
    mycf->upstream.connect_timeout = 60000;
    mycf->upstream.send_timeout = 60000;
    mycf->upstream.read_timeout = 60000;
    mycf->upstream.store_access = 0600;

    /*�������η��������巽ʽ��أ������Թ̶�bufferת������*/
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;
    mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;


    /*upstreamģ��Ҫ��hide_headers�����ʼ��*/
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

/*upstream  create_request �ص������������η�����������*/
static ngx_int_t
mytest_upstream_create_request(ngx_http_request_t *r)
{
    /*ģ��baidu�������� /s?wd= */
    static ngx_str_t backendQueryLine =
        ngx_string("GET /s?wd=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");

    /*���󳤶� -2��ʾ %V*/
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;

    /*�ڴ�������ڴ棬�������ʱ�ڴ汻�Զ��ͷ�*/
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL)
        return NGX_ERROR;

    /*lastҪָ�������ĩβ*/
    b->last = b->pos + queryLineLen;

    /*�����൱��snprintf*/
    ngx_snprintf(b->pos, queryLineLen ,(char*)backendQueryLine.data, &r->args);

    /*���͸����η�����������*/
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL)
        return NGX_ERROR;

    /*request_bufs����ֻ����1��ngx_buf_t������*/
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    /*header_hash������Ϊ0*/
    r->header_hash = 1;
    return NGX_OK;
}



static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    /*ȡ��http�����������*/
    ngx_http_mytest_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (ctx == NULL)
    {
        return NGX_ERROR;
    }

    u = r->upstream;

    /*����http��Ӧ��*/
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    /*NGX_AGAIN��ʾ��������*/
    if (rc == NGX_AGAIN)
    {
        return rc;
    }

    /*NGX_ERRORû�н��յ��Ϸ���http��Ӧ��*/
    if (rc == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    /*��������������Ӧ�У����������������ݸ�ֵ��headers_in�ṹ����*/
    if (u->state)
    {
        u->state->status = ctx->status.code;
    }

    /*��ֵ����*/
    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;

    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL)
    {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len); 


    /*��ʼ����http��Ӧͷ��*/
    /*֮���յ������ַ��������µĻص���������*/
    u->process_header = mytest_upstream_process_header;

    /*��������յ����ַ�������http��Ӧ���⣬���ж�����ַ�*/
    /*����mytest_upstream_process_header��������*/
    return mytest_upstream_process_header(r);
}


/*����httpͷ��*/
static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc;

    /*Ϊhttpͷ����������*/
    /*���� key �洢"Content-Length"*/
    /*value �洢 "1024" */
    ngx_table_elt_t *h;

    ngx_http_upstream_header_t     *hh;

    ngx_http_upstream_main_conf_t  *umcf;

    /*��upstreamģ��������ngx_http_upstream_main_conf_tȡ��*/
    /*�ýṹ���д洢����Ҫ��ͳһ������httpͷ�����ƺͻص�����*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    /*ѭ���Ľ������е�httpͷ��*/
    for ( ;; )
    {
    /*����httpͷ��*/
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        /*NGX_OK������һ��httpͷ��*/
        if (rc == NGX_OK)
        {
            /*��headers_in.headers���ngx_list_t����������httpͷ��*/
        /*ngx_list_t���Ȳ����ٸ�ֵ*/
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL)
            {
                return NGX_ERROR;
            }

            /*����ո����ӵ�headers�����е�httpͷ��*/
            h->hash = r->header_hash;

        /*key-ͷ������ value-��Ӧ��ֵ*/
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;


        /*zx:�������������ô��ռ��ԭ�����ڣ��ڽṹ��������������*/
        //1.key
        //2.value
        //3.lowcase_case
        /*һ��������һ���οռ䣬+1����'\0'������*/
        /*��Ҳ����ngx_str_t����������data�ֶμ�¼��ֻ���ִ���ַ*/
            h->key.data = ngx_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL)
            {
                return NGX_ERROR;
            }

        /*��ֵ����*/
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

            /*upstreamģ����һЩhttpͷ�������⴦��*/
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }

        /*����NGX_HTTP_PARSE_HEADER_DONE��ʾ��Ӧ�����е�httpͷ��������*/
        if (rc == NGX_HTTP_PARSE_HEADER_DONE)
        {
            /*���֮ǰ����httpͷ��ʱû�з���server��dateͷ��*/
        /*��httpЭ������������ͷ��*/
            if (r->upstream->headers_in.server == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

        /*zx:�鿴ngx_hash_key_lc/ngx_hash_keyԴ���֪�����Ը�д*/
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
        /*zx:ͬ��*/
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

    /*û�н�����������httpͷ�������������µ��ַ���*/
        if (rc == NGX_AGAIN)
        {
            return NGX_AGAIN;
        }

        /*��������ֵ���ǷǷ���*/
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

/*finalize_request�ص� �������ǰ�����*/
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

    /*�����ҵ�mytest���������������ÿ飬clcfò����location���ڵ�����*/
    /*�ṹ����ʵ��Ȼ����������main��srv����loc���������Ҳ����˵��ÿ��*/
    /*http{}��server{}��Ҳ����һ��ngx_http_core_loc_conf_t�ṹ��*/
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    /*http����ڴ����û�������е�NGX_HTTP_CONTENT_PHASE�׶�ʱ�����*/
    /*���������������URI��mytest���������ڵ����ÿ���ƥ�䣬�ͽ���������*/
    /*ʵ�ֵ�ngx_http_mytest_handler���������������*/
    clcf->handler = ngx_http_mytest_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
    /*���Ƚ���http�����Ľṹ��ngx_http_mytest_ctx_t*/
    ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (myctx == NULL)
    {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL)
        {
            return NGX_ERROR;
        }
        /*���½����������������������*/
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
    }

    /*��ÿ1��Ҫʹ��upstream�����󣬱��������ֻ�ܵ���1��*/
    /*ngx_http_upstream_create�����������ʼ��r->upstream��Ա*/
    if (ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    /*�õ�����upstream�ṹ��ngx_http_mytest_conf_t*/
    ngx_http_mytest_conf_t  *mycf = (ngx_http_mytest_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);

    /*����upstream*/
    ngx_http_upstream_t *u = r->upstream;

    /*�����������ļ��еĽṹ��������r->upstream->conf��Ա*/
    /*ngx_http_upstream_conf_t�ṹ*/
    u->conf = &mycf->upstream;

    /*����ת������ʱʹ�õĻ�����*/
    u->buffering = mycf->upstream.buffering;

    /*���´��뿪ʼ��ʼ��resolved�ṹ�壬�����������η������ĵ�ַ*/

    u->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    /*��������η���������www.baidu.com*/
    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*) "www.baidu.com");
    if (pHost == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gethostbyname fail. %s", strerror(errno));

        return NGX_ERROR;
    }

    /*�������η�������80�˿�*/
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);

    memcpy(&backendSockAddr.sin_addr,pHost->h_addr_list[0],sizeof(struct in_addr));
    char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    /*inet_addr*/
    //backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    /*����ַ���õ�resolved��Ա��*/
    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;

    //add by sgy from web
    u->resolved->port = htons((in_port_t)80);

    /*������������ʵ�ֵĻص�����:�������󡢴���ͷ������������*/
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;

    /*������뽫count��Ա��1*/
    r->main->count++;
    /*����upstream*/
    ngx_http_upstream_init(r);
    /*���뷵��NGX_DONE*/
    return NGX_DONE;
}