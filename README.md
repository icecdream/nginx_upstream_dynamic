# nginx_upstream_dynamic

`nginx_upstream_dynamic` is the module for dynamically modify upstreams, currently supports parsing nginx variable key to dynamically modify upstream servers.

`dynamickey` fromat: 127.0.0.1:5678;127.0.0.1:5679;127.0.0.1:5680

# Quick Start

priority use $arg_dynamickey parsed servers, after all parsed server down, use backend_test server, the following example is 127.0.0.1:5555.

```nginx
upstream backend_test {
    dynamickey $arg_dynamickey;
    server 127.0.0.1:5555 max_fails=10 fail_timeout=5s weight=1;
    keepalive 4096;
}

server {
    listen 6789;

    location /upstream_test {
        proxy_pass http://backend_test;
        proxy_http_version 1.1;
        proxy_set_header Connection "Keep-Alive";
        proxy_connect_timeout 10ms;
        proxy_send_timeout 10ms;
        proxy_read_timeout 10ms;
        proxy_next_upstream off;
    }
}
```

