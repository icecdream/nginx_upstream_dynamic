
/*
 * Copyright (C) Dong
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                           last_servers_key;
    ngx_http_complex_value_t            key;     // 指令参数 在脚本引擎编译后的key

    ngx_http_upstream_init_pt           original_init_upstream;  // 原始的init_upstream函数(默认为RR) 将init_upstream替换为本模块函数ngx_http_upstream_init_keepalive，在函数中调用原来的init_upstream函数  相当于hook了下
    ngx_http_upstream_init_peer_pt      original_init_peer;      // 原始的init_peer函数 同上


    // server param
    time_t                              fail_timeout;
    ngx_int_t                           max_conns;
    ngx_int_t                           max_fails;

    // original servers(ip_hash not support backup)
    ngx_array_t                        *original_servers;		// save origin servers
    ngx_int_t                           original_servers_index;

    // conf pool
    ngx_conf_t                         *cf;
    ngx_conf_t                          conf1;
    ngx_conf_t                          conf2;
    unsigned                            use_conf1:1;

} ngx_http_upstream_dynamic_srv_conf_t;

typedef struct {
    ngx_http_upstream_dynamic_srv_conf_t   *conf;

    void                              *data;
    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

    unsigned                           use_original_servers:1;

} ngx_http_upstream_dynamic_peer_data_t;


static ngx_int_t ngx_http_upstream_init_dynamic_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_get_dynamic_peer(ngx_peer_connection_t *pc, 
    void *data);
static void ngx_http_upstream_free_dynamic_peer(ngx_peer_connection_t *pc, 
    void *data, ngx_uint_t state);

static void *ngx_http_upstream_dynamic_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_dynamickey(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_dynamic_parse_dynamickey(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_dynamic_parse_servers(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us, 
    ngx_str_t *cf_servers);


static ngx_command_t  ngx_http_upstream_dynamic_commands[] = {

    { ngx_string("dynamickey"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_dynamickey,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_dynamic_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_dynamic_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_dynamic_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_dynamic_module_ctx, /* module context */
    ngx_http_upstream_dynamic_commands,    /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_dynamic(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_server_t              *server;
    ngx_http_upstream_dynamic_srv_conf_t    *dcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init dynamic upstream");

    dcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_dynamic_module);

    // 调用原始的init_upstream函数
    if (dcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    dcf->original_init_peer = us->peer.init;
    us->peer.init = ngx_http_upstream_init_dynamic_peer;

    // 保存servers参数  upstream块最少一个server
    dcf->original_servers = us->servers;

    server = us->servers->elts;
    dcf->fail_timeout = server[0].fail_timeout;
    dcf->max_conns = server[0].max_conns;
    dcf->max_fails = server[0].max_fails;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_dynamic_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_dynamic_peer_data_t    *dp;
    ngx_http_upstream_dynamic_srv_conf_t     *dcf;

    dcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_dynamic_module);

    // 解析dynamickey
    ngx_http_dynamic_parse_dynamickey(r, us);

    dp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_dynamic_peer_data_t));
    if (dp == NULL) {
        return NGX_ERROR;
    }

    // 首先调用原始的init_peer函数 默认为ngx_http_upstream_init_round_robin_peer，在函数中会分配peer.get/peer.free等函数指针
    if (dcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    // 将peer.get/peer.free等替换为当前模块对应函数
    dp->conf = dcf;
    dp->data = r->upstream->peer.data;
    dp->original_get_peer = r->upstream->peer.get;
    dp->original_free_peer = r->upstream->peer.free;
    dp->use_original_servers = 0;

    r->upstream->peer.data = dp;
    r->upstream->peer.get = ngx_http_upstream_get_dynamic_peer;
    r->upstream->peer.free = ngx_http_upstream_free_dynamic_peer;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_dynamic_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_dynamic_peer_data_t   *dp = data;
    ngx_int_t          rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get upstream dynamic peer");

    /* ask balancer */
    rc = dp->original_get_peer(pc, dp->data);
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    // original_get_peer未成功获取server 使用原始的代理server
    dp->use_original_servers = 1;
    pc->cached = 0;
    pc->connection = NULL;

    ngx_http_upstream_server_t *original_servers = dp->conf->original_servers->elts;
    uint32_t index = (dp->conf->original_servers_index++) % dp->conf->original_servers->nelts;
    
    pc->sockaddr = original_servers[index].addrs[0].sockaddr;
    pc->socklen = original_servers[index].addrs[0].socklen;
    pc->name = &original_servers[index].addrs[0].name;
    ngx_log_error(NGX_LOG_WARN, pc->log, 0, "upstream dynamic original get peer failed, use original servers index:%d, name:%V", index, pc->name);

    return NGX_OK;
}

static void
ngx_http_upstream_free_dynamic_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_upstream_dynamic_peer_data_t   *dp = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                "free upstream dynamic peer");

    if (dp->use_original_servers == 0) {
        dp->original_free_peer(pc, dp->data, state);
    } else {
        ngx_log_error(NGX_LOG_WARN, pc->log, 0, "upstream dynamic dont free, all failed use RR origin servers");
    }
}

static void *
ngx_http_upstream_dynamic_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_dynamic_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_dynamic_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->original_init_upstream = NULL;
    conf->original_init_peer = NULL;
    conf->fail_timeout = 10;
    conf->max_conns = 0;
    conf->max_fails = 1;
    conf->original_servers_index = 0;
    conf->original_servers = NULL;
    conf->use_conf1 = 0;

    // set conf->conf1
    ngx_memzero(&conf->conf1, sizeof(ngx_conf_t));
    conf->conf1.pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, ngx_cycle->log);
    if (conf->conf1.pool == NULL) {
        return NULL;
    }
    conf->conf1.cycle = (ngx_cycle_t *) ngx_cycle;
    conf->conf1.log = ngx_cycle->log;

    // set conf->cf2
    ngx_memzero(&conf->conf2, sizeof(ngx_conf_t));
    conf->conf2.pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, ngx_cycle->log);
    if (conf->conf2.pool == NULL) {
        return NULL;
    }
    conf->conf2.cycle = (ngx_cycle_t *) ngx_cycle;
    conf->conf2.log = ngx_cycle->log;

    conf->cf = conf->use_conf1 ? &conf->conf1 : &conf->conf2;

    return conf;
}

static char *
ngx_http_upstream_dynamickey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_dynamic_srv_conf_t  *dcf = conf;

    ngx_str_t                         *value;
    ngx_http_upstream_srv_conf_t      *uscf;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &dcf->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    // 保存原来的init_upstream  默认为ngx_http_upstream_init_round_robin
    dcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    // 将init_upstream替换为ngx_http_upstream_init_keepalive 在函数内部调用原始的init_upstream
    uscf->peer.init_upstream = ngx_http_upstream_init_dynamic;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dynamic_parse_dynamickey(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                                 rc;
    ngx_str_t                                 key;
    ngx_http_upstream_dynamic_srv_conf_t     *dcf;
    ngx_http_upstream_init_peer_pt            backup_upstream_init_peer;

    dcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_dynamic_module);

    // 指令参数 每次请求的具体值
    if (ngx_http_complex_value(r, &dcf->key, &key) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream dynamic upstream parse dynamickey failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream dynamic upstream key:\"%V\"", &key);

    
    rc = ngx_http_dynamic_parse_servers(r, us, &key);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream dynamic upstream parse servers %V failed", &key);
        return rc;        
    }

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "upstream dynamic upstream key %V success", &key);

        backup_upstream_init_peer = us->peer.init;
        dcf->cf = dcf->use_conf1 ? &dcf->conf2 : &dcf->conf1;   // 空闲内存池申请数据
        if (ngx_http_upstream_init_round_robin(dcf->cf, us) == NGX_OK) {
            // 更新RR列表成功  备份当前的serverskey
            dcf->last_servers_key.len = key.len;
            dcf->last_servers_key.data = ngx_pnalloc(dcf->cf->pool, dcf->last_servers_key.len);
            if (dcf->last_servers_key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dynamic upstream copy servers_key ngx_pnalloc failed");
                return NGX_ERROR;
            }
            ngx_memcpy(dcf->last_servers_key.data, key.data, dcf->last_servers_key.len);

            dcf->use_conf1 = !dcf->use_conf1;
            
        } else {
            // 更新RR列表失败 内存不足时可能失败 不影响RR的us->peer.data
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream dynamic upstream key %V, init RR failed", &key);
        }

        us->peer.init = backup_upstream_init_peer;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dynamic_parse_servers(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us, ngx_str_t *cf_servers)
{
    ngx_url_t                   u;
    uint32_t                    i = 0;
    uint32_t                    j = 0;
    ngx_conf_t                               *free_conf;
    ngx_http_upstream_dynamic_srv_conf_t     *dcf;
    dcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_dynamic_module);

    if (cf_servers->len == 0) {
        return NGX_DONE;
    }

    if (cf_servers->len == dcf->last_servers_key.len && ngx_strncmp(cf_servers->data, dcf->last_servers_key.data, dcf->last_servers_key.len) == 0 ) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "upstream dynamic cf_servers:%V same as last", cf_servers);
        return NGX_DONE;
    }

    // parse cf_servers
    free_conf = dcf->use_conf1 ? &dcf->conf2 : &dcf->conf1;
    ngx_reset_pool(free_conf->pool);

    ngx_array_t *dynamic_servers = ngx_array_create(free_conf->pool, 20, sizeof(ngx_http_upstream_server_t));
    if (dynamic_servers == NULL) {
        return NGX_ERROR;
    }

    for ( ; i<=cf_servers->len; ++i) {
        // parse one server
        if (i == cf_servers->len || cf_servers->data[i] == ';') {
            ngx_http_upstream_server_t *server = ngx_array_push(dynamic_servers);
            if (server == NULL)
                return NGX_ERROR;
            
            ngx_memzero(&u, sizeof(ngx_url_t));
            u.url.data = cf_servers->data + j;
            u.url.len = i - j;
            j = i + 1;
            u.default_port = 80;
            if (ngx_parse_url(free_conf->pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dynamic upstream err:%s in \"%V\"", u.err, &u.url);
                }
                return NGX_ERROR;
            }

            ngx_memzero(server, sizeof(ngx_http_upstream_server_t));
            server->name = u.url;
            server->addrs = u.addrs;
            server->naddrs = u.naddrs;
            server->weight = 1;
            server->max_conns = dcf->max_conns;
            server->max_fails = dcf->max_fails;
            server->fail_timeout = dcf->fail_timeout;
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dynamic upstream add server name:%V, naddrs:%d max_conns:%d max_fails:%d fail_timeout:%d backup:%d", 
                                                &server->name, server->naddrs, server->max_conns, server->max_fails, server->fail_timeout, server->backup);
        }
    }

    // replace conf and servers
    us->servers = dynamic_servers;

    return NGX_OK;
}

