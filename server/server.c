/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
//#include "h2o/memcached.h"
#ifndef H2O_USE_HTTP3
#define H2O_USE_HTTP3 1
#endif
#ifndef H2O_USE_LIBUV
#define H2O_USE_LIBUV 0
#endif

// HTTP3 stuff
#include "h2o/http3_server.h"
#include "h2o/http3_common.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
///

// Stuff used by me
#include <assert.h>
///


#define USE_HTTPS 1
#define USE_MEMCACHED 0

// LOCAL = true <=> local development
#ifndef LOCAL
#define LOCAL 0
#endif

#if LOCAL
    // march=native
    #define DOMAIN 0x7f000001
    #define DOMAIN_STR "127.0.0.1"
    #define HTTP_PORT 23230
    #define HTTP_PORT_STR "23230"
    #define HTTPS_PORT 23231
    #define HTTPS_PORT_STR "23231"
    #define HTTP3_PORT 23232
    #define HTTP3_PORT_STR "23232"

    // TODO change certs for local dev
    #define CERTIFICATE_FILEPATH "/etc/letsencrypt/live/spiel.crabdance.com/fullchain.pem"
    #define PRIVATE_KEY_FILEPATH "/etc/letsencrypt/live/spiel.crabdance.com/privkey.pem"
#else
    // march=haswell
    #define DOMAIN INADDR_ANY
    #define DOMAIN_STR "0.0.0.0"
    #define HTTP_PORT 80
    #define HTTP_PORT_STR "80"
    #define HTTPS_PORT 443
    #define HTTPS_PORT_STR "443"
    #define HTTP3_PORT 443
    #define HTTP3_PORT_STR "443"

    #define CERTIFICATE_FILEPATH "/etc/letsencrypt/live/spiel.crabdance.com/fullchain.pem"
    #define PRIVATE_KEY_FILEPATH "/etc/letsencrypt/live/spiel.crabdance.com/privkey.pem"
#endif

static h2o_pathconf_t* register_handler(h2o_hostconf_t* hostconf, const char* path, int (*on_req)(h2o_handler_t*, h2o_req_t*))
{
    h2o_pathconf_t* pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t* handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}

// // sends index.html
// // isn't using a default file handler because of the need of Alt-Svc
static int add_alt_svc_handler(h2o_handler_t* self, h2o_req_t* req)
{
    /* only advertise HTTP/3 for TLS (HTTPS) requests */
    if (req->scheme == &H2O_URL_SCHEME_HTTPS) {
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ALT_SVC, NULL,
            H2O_STRLIT("h3=\":" HTTP3_PORT_STR "\"; ma=3600"));
    }
    /* return -1 so the next handler (the file handler) can still handle the request */
    return -1;
}

static h2o_globalconf_t config;
static h2o_context_t ctx;
//static h2o_multithread_receiver_t libmemcached_receiver;
static h2o_accept_ctx_t accept_ctx;
static h2o_accept_ctx_t accept_ctx_plain;

static h2o_http3_server_ctx_t http3_ctx;
static quicly_context_t quic_ctx;
static ptls_context_t ptls_ctx;
static ptls_openssl_sign_certificate_t sign_certificate;
static quicly_cid_plaintext_t next_cid;
static h2o_accept_ctx_t http3_accept_ctx;

// accept http
static void on_accept_plain(h2o_socket_t* listener, const char* err)
{
    // I could've refactored this to a purer function and not just copypaste of on_accept, but I am too lazy and this works good enough
    h2o_socket_t* sock;

    if (err != NULL) {
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
    h2o_accept(&accept_ctx_plain, sock);
}

// accept https
static void on_accept(h2o_socket_t* listener, const char* err)
{
    h2o_socket_t* sock;

    if (err != NULL) {
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
    h2o_accept(&accept_ctx, sock);
}

// copypaste of create_listener, but for http instead of https
static int create_plain_listener(void)
{
    struct sockaddr_in addr;
    int fd, reuseaddr_flag = 1;
    h2o_socket_t* sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(DOMAIN);
    addr.sin_port = htons(HTTP_PORT);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
        bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
        return -1;
    }

    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(sock, on_accept_plain);

    return 0;
}

static int create_listener(void)
{
    struct sockaddr_in addr;
    int fd, reuseaddr_flag = 1;
    h2o_socket_t* sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(DOMAIN);
    addr.sin_port = htons(HTTPS_PORT);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
        bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
        return -1;
    }

    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(sock, on_accept);

    return 0;
}

// HTTP3 stuff
// ig, cb stands for callback
static int on_client_hello_cb(ptls_on_client_hello_t* self, ptls_t* tls, ptls_on_client_hello_parameters_t* params)
{
    if (params->incompatible_version)
        return 0;

    if (params->negotiated_protocols.count != 0) {
        size_t i, j;
        for (i = 0; i != sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn[0]); ++i) {
            for (j = 0; j != params->negotiated_protocols.count; ++j)
                if (h2o_memis(h2o_http3_alpn[i].base, h2o_http3_alpn[i].len, params->negotiated_protocols.list[j].base,
                    params->negotiated_protocols.list[j].len))
                    goto Found;
        }
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    Found: {
        int ret = ptls_set_negotiated_protocol(tls, (const char*)h2o_http3_alpn[i].base, h2o_http3_alpn[i].len);
        if (ret != 0)
            return ret;
        }
    }
    return 0;
}

static ptls_on_client_hello_t on_client_hello = { on_client_hello_cb }; // funny syntax

static int setup_ptls_context(const char* cert_file, const char* key_file)
{
    ptls_ctx = (ptls_context_t){
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
        .sign_certificate = &sign_certificate.super,
        .on_client_hello = &on_client_hello,
    };

    if (ptls_load_certificates(&ptls_ctx, cert_file) != 0) {
        fprintf(stderr, "failed to load certificates from %s\n", cert_file);
        return -1;
    }

    FILE* fp = fopen(key_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "failed to open key file: %s\n", key_file);
        return -1;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "failed to load private key from %s\n", key_file);
        return -1;
    }

    if (ptls_openssl_init_sign_certificate(&sign_certificate, pkey) != 0) {
        fprintf(stderr, "failed to setup private key\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_free(pkey);

    return 0;
}

static int setup_quic_context(void)
{
    static uint8_t cid_key[32] = { 0 };
    ptls_openssl_random_bytes(cid_key, sizeof(cid_key));

    quic_ctx = quicly_spec_context;
    quic_ctx.tls = &ptls_ctx;
    quic_ctx.now = &quicly_default_now;
    quic_ctx.init_cc = &quicly_default_init_cc;
    quic_ctx.crypto_engine = &quicly_default_crypto_engine;

    quic_ctx.cid_encryptor =
        quicly_new_default_cid_encryptor(&ptls_openssl_aes128ecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
            ptls_iovec_init(cid_key, sizeof(cid_key)));
    if (quic_ctx.cid_encryptor == NULL) {
        fprintf(stderr, "failed to create CID encryptor\n");
        return -1;
    }

    quicly_amend_ptls_context(&ptls_ctx);
    h2o_http3_server_amend_quicly_context(&config, &quic_ctx);

    next_cid = (quicly_cid_plaintext_t){
        .master_id = 0,
        .thread_id = 0,
        .node_id = 0,
    };

    return 0;
}

static int create_udp_listener(h2o_socket_t** sock_out)
{
    struct sockaddr_in addr;
    int fd, optval = 1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(DOMAIN);
    addr.sin_port = htons(HTTP3_PORT);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket(SOCK_DGRAM)");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

#if defined(IP_PKTINFO)
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(IP_PKTINFO)");
        close(fd);
        return -1;
    }
#elif defined(IP_RECVDSTADDR)
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(IP_RECVDSTADDR)");
        close(fd);
        return -1;
    }
#endif

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind(UDP)");
        close(fd);
        return -1;
    }

    h2o_socket_set_df_bit(fd, AF_INET);

    /* QUIC reads datagrams directly using recvmsg / recvmmsg; prevent the socket layer from consuming UDP payloads. */
    *sock_out = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);

    return 0;
}

static h2o_quic_conn_t* on_http3_accept(
    h2o_quic_ctx_t* quic_ctx, quicly_address_t* destaddr, quicly_address_t* srcaddr, quicly_decoded_packet_t* packet)
{
    h2o_http3_server_ctx_t* h3ctx = H2O_STRUCT_FROM_MEMBER(h2o_http3_server_ctx_t, super, quic_ctx);

    h2o_http3_conn_t* conn = h2o_http3_server_accept(h3ctx, destaddr, srcaddr, packet, NULL, &H2O_HTTP3_CONN_CALLBACKS);

    if (conn == NULL) {
        return NULL;
    }
    if (&conn->super == &h2o_quic_accept_conn_decryption_failed) {
        return NULL;
    }
    if (conn == &h2o_http3_accept_conn_closed) {
        return NULL;
    }

    return &conn->super;
}

/// end of HTTP3 stuff

static int setup_ssl(const char* cert_file, const char* key_file, const char* ciphers)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
                                    // 23 mentioned!
    accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

    // AFAIK memcached is kinda useless for 1 server
    // if (USE_MEMCACHED) {
    //     accept_ctx.libmemcached_receiver = &libmemcached_receiver;
    //     h2o_accept_setup_memcached_ssl_resumption(
    //         h2o_memcached_create_context(
    //             DOMAIN_STR, // maybe this should always be localhost???
    //             11211, // port
    //             0,     // text_protocol
    //             1,     // num_threads (so, 1 thread...)
    //             "h2o:ssl-resumption:" // prefix
    //         ),       
    //         86400 // expiration, possible 1 day
    //     );
    //     h2o_socket_ssl_async_resumption_setup_ctx(accept_ctx.ssl_ctx);
    // }

#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(accept_ctx.ssl_ctx, 1);
#endif

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_chain_file(accept_ctx.ssl_ctx, cert_file) != 1) {
        fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
        return -1;
    }

    if (SSL_CTX_set_cipher_list(accept_ctx.ssl_ctx, ciphers) != 1) {
        fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
        return -1;
    }

    /* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(accept_ctx.ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return 0;
}


void process_html(const char* dir, const char* name, const char* new_name) {
    assert(strlen(dir) + strlen(name) + 2 <= 256);
    char cstr[256] = "";
    strcpy(cstr, dir);
    strcat(cstr, "/");
    strcat(cstr, name);
    FILE* file = fopen(cstr, "r");
    if (!file) {
        // file doesn't exist
        puts(cstr);
        perror("fopen r");
        abort();
    }
    fseek(file, 0, SEEK_END);
    int file_sz = ftell(file);
    if (file_sz < 0) {
        perror("ftell < 0");
        fclose(file);
        abort();
    }
    fseek(file, 0, SEEK_SET);
    constexpr int buffer_size = 10000;
    char buffer[buffer_size] = {};
    int bytes_read = fread(buffer, 1, file_sz, file);
    if (bytes_read != file_sz) {
        perror("bytes_read != file_sz");
        fclose(file);
        abort();
    }
    buffer[bytes_read] = '\0';

    const char marker_start[] = "<!-- #include("; // Yeah, if you add extra spaces this function will break
    const char marker_end[] = ") -->";
    const int len_start = strlen(marker_start);
    const int len_end = strlen(marker_end);

    char* str_start = strstr(buffer, marker_start);
	char* str_end = strstr(buffer, marker_end);

    while (str_start && str_end) {
        char* part_after = strdup(str_end + len_end);

        str_end[0] = '\0';
        const char* PATH = str_start + len_start;
        assert(strlen(dir) + strlen(PATH) + 2 <= 256);
        char dstr[256] = "";
        strcpy(dstr, dir);
        strcat(dstr, "/");
        strcat(dstr, PATH);
        
        FILE* f = fopen(dstr, "r");
        if (!f) {
            puts(dstr);
            perror("fopen");
            abort();
        }
        fseek(f, 0, SEEK_END);
        int size = ftell(f);
        bytes_read += size;
        fseek(f, 0, SEEK_SET);

        str_start[0] = '\0';
        const int index = strlen(buffer);
        memset(str_start, 0, file_sz - index);

        fread(buffer + index, 1, size, f);
        buffer[index + size] = '\0'; // should be unnecessary
        strcat(buffer, part_after);

        fclose(f);
        char* after_start = strstr(part_after, marker_start);
        char* after_end = strstr(part_after, marker_end);
        if (!after_start || !after_end) {
            free(part_after);
            break;
        }
        str_start += after_start - part_after;
        str_end   += after_end   - part_after;
        free(part_after);
    }

    if (buffer_size < bytes_read) {
        printf("buffersize: %d\nbytes_read: %ld\n", buffer_size, bytes_read);
        puts("Make buffersize larger!");
        fclose(file);
        abort();
    }
    fclose(file);
    memset(cstr, 0, 256);
    strcpy(cstr, dir);
    strcat(cstr, "/");
    strcat(cstr, new_name);
    FILE* saved_file = fopen(cstr, "w");
    if (!saved_file) {
        puts(cstr);
        perror("fopen w");
        abort();
    }
    fprintf(saved_file, "%s", buffer);
    fclose(saved_file);
}







int main(int argc, char** argv)
{

    // changing files
    process_html(".", "index_before_preprocessing.html", "index.html");

    h2o_hostconf_t* hostconf;
    h2o_access_log_filehandle_t* logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
    h2o_pathconf_t* pathconf;

    signal(SIGPIPE, SIG_IGN);

    h2o_config_init(&config);
    hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

    //pathconf = register_handler(hostconf, "/post-test", post_test);
    //if (logfh != NULL)
    //    h2o_access_log_register(pathconf, logfh);
    //
    //pathconf = register_handler(hostconf, "/chunked-test", chunked_test);
    //if (logfh != NULL)
    //    h2o_access_log_register(pathconf, logfh);
    //
    //pathconf = register_handler(hostconf, "/reproxy-test", reproxy_test);
    //h2o_reproxy_register(pathconf);
    //if (logfh != NULL)
    //    h2o_access_log_register(pathconf, logfh);
    //
    //pathconf = h2o_config_register_path(hostconf, "/", 0);
    //h2o_file_register(pathconf, "examples/doc_root", NULL, NULL, 0);
    //if (logfh != NULL)
    //    h2o_access_log_register(pathconf, logfh);

    pathconf = h2o_config_register_path(hostconf, "/", 0);
    {
        h2o_handler_t* handler = h2o_create_handler(pathconf, sizeof(*handler));
        handler->on_req = add_alt_svc_handler;
    }
    const char* index_files[] = { "index.html", NULL };
    h2o_file_register(pathconf, ".", index_files, NULL, 0);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);


    h2o_context_init(&ctx, h2o_evloop_create(), &config);

    //if (USE_MEMCACHED)
    //    h2o_multithread_register_receiver(ctx.queue, &libmemcached_receiver, h2o_memcached_receiver);

    if (USE_HTTPS && setup_ssl(CERTIFICATE_FILEPATH, PRIVATE_KEY_FILEPATH,
        "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
        goto Error;

    accept_ctx.ctx = &ctx;
    accept_ctx.hosts = config.hosts;

    if (create_listener() != 0) {
        fprintf(stderr, "failed to listen to " DOMAIN_STR ":" HTTPS_PORT_STR ":%s\n", strerror(errno));
        goto Error;
    }
    printf("HTTP/1 and HTTP/2 listening on https://" DOMAIN_STR ":" HTTPS_PORT_STR " (TCP)\n");

    if (setup_ptls_context(CERTIFICATE_FILEPATH, PRIVATE_KEY_FILEPATH) != 0)
        goto Error;

    if (setup_quic_context() != 0)
        goto Error;

    h2o_socket_t* udp_sock;
    if (create_udp_listener(&udp_sock) != 0) {
        fprintf(stderr, "failed to create UDP listener on " DOMAIN_STR ":" HTTP3_PORT_STR "\n");
        goto Error;
    }

    http3_accept_ctx.ctx = &ctx;
    http3_accept_ctx.hosts = config.hosts;

    h2o_http3_server_init_context(
        &ctx, // "this" for h2o "object". C moment
        &http3_ctx.super, // inheritance in my favourite OOP language
        ctx.loop, 
        udp_sock,
        (h2o_socket_t*) NULL, // sock_alt_family
        &quic_ctx, 
        &next_cid, 
        on_http3_accept, 
        (h2o_quic_notify_connection_update_cb) NULL,
        config.http3.use_gso // Generic Segmentation Offload enabled
    );
    http3_ctx.accept_ctx = &http3_accept_ctx;

    printf("HTTP/3 listening on https://" DOMAIN_STR ":" HTTP3_PORT_STR " (UDP/QUIC)\n");


    while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
        ;

Error:
    return 1;
}
