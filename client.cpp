#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL -1

struct TraceEnter
{
    TraceEnter(const char file[], long line, const char func_name[])
    {
        this->file = &file[0],
        this->line = line,
        this->func_name = &func_name[0];
        printf("[PHUONG] %s:%d %s {\n", file, line, func_name);
    }
    ~TraceEnter()
    {
        printf("[PHUONG] %s:%ld %s }\n", file, line, func_name);
    }
    const char *file;
    const char *func_name;
    int line;
};

#define TRACE_ENTER TraceEnter \
entry(__FILE__, __LINE__, __PRETTY_FUNCTION__)

int OpenConnection(const char *hostname, int port)
{
    TRACE_ENTER;
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    printf("Prepare gethostbyname()\n");
    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    printf("Prepare create socket\n");
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    printf("Prepare to connect\n");
    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

const char *tls_rt_type(int type)
{
    TRACE_ENTER;
    switch (type)
    {
#ifdef SSL3_RT_HEADER
    case SSL3_RT_HEADER:
        return "TLS header";
#endif
    case SSL3_RT_CHANGE_CIPHER_SPEC:
        return "TLS change cipher";
    case SSL3_RT_ALERT:
        return "TLS alert";
    case SSL3_RT_HANDSHAKE:
        return "TLS handshake";
    case SSL3_RT_APPLICATION_DATA:
        return "TLS app data";
    default:
        return "TLS Unknown";
    }
}

const char *ssl_msg_type(int ssl_ver, int msg)
{
    TRACE_ENTER;
#ifdef SSL2_VERSION_MAJOR
    if (ssl_ver == SSL2_VERSION_MAJOR)
    {
        switch (msg)
        {
        case SSL2_MT_ERROR:
            return "Error";
        case SSL2_MT_CLIENT_HELLO:
            return "Client hello";
        case SSL2_MT_CLIENT_MASTER_KEY:
            return "Client key";
        case SSL2_MT_CLIENT_FINISHED:
            return "Client finished";
        case SSL2_MT_SERVER_HELLO:
            return "Server hello";
        case SSL2_MT_SERVER_VERIFY:
            return "Server verify";
        case SSL2_MT_SERVER_FINISHED:
            return "Server finished";
        case SSL2_MT_REQUEST_CERTIFICATE:
            return "Request CERT";
        case SSL2_MT_CLIENT_CERTIFICATE:
            return "Client CERT";
        }
    }
    else
#endif
        if (ssl_ver == SSL3_VERSION_MAJOR)
    {
        switch (msg)
        {
        case SSL3_MT_HELLO_REQUEST:
            return "Hello request";
        case SSL3_MT_CLIENT_HELLO:
            return "Client hello";
        case SSL3_MT_SERVER_HELLO:
            return "Server hello";
#ifdef SSL3_MT_NEWSESSION_TICKET
        case SSL3_MT_NEWSESSION_TICKET:
            return "Newsession Ticket";
#endif
        case SSL3_MT_CERTIFICATE:
            return "Certificate";
        case SSL3_MT_SERVER_KEY_EXCHANGE:
            return "Server key exchange";
        case SSL3_MT_CLIENT_KEY_EXCHANGE:
            return "Client key exchange";
        case SSL3_MT_CERTIFICATE_REQUEST:
            return "Request CERT";
        case SSL3_MT_SERVER_DONE:
            return "Server finished";
        case SSL3_MT_CERTIFICATE_VERIFY:
            return "CERT verify";
        case SSL3_MT_FINISHED:
            return "Finished";
#ifdef SSL3_MT_CERTIFICATE_STATUS
        case SSL3_MT_CERTIFICATE_STATUS:
            return "Certificate Status";
#endif
#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
        case SSL3_MT_ENCRYPTED_EXTENSIONS:
            return "Encrypted Extensions";
#endif
#ifdef SSL3_MT_SUPPLEMENTAL_DATA
        case SSL3_MT_SUPPLEMENTAL_DATA:
            return "Supplemental data";
#endif
#ifdef SSL3_MT_END_OF_EARLY_DATA
        case SSL3_MT_END_OF_EARLY_DATA:
            return "End of early data";
#endif
#ifdef SSL3_MT_KEY_UPDATE
        case SSL3_MT_KEY_UPDATE:
            return "Key update";
#endif
#ifdef SSL3_MT_NEXT_PROTO
        case SSL3_MT_NEXT_PROTO:
            return "Next protocol";
#endif
#ifdef SSL3_MT_MESSAGE_HASH
        case SSL3_MT_MESSAGE_HASH:
            return "Message hash";
#endif
        }
    }
    return "Unknown";
}

static void ossl_trace(int direction, int ssl_ver, int content_type,
                       const void *buf, size_t len, SSL *ssl,
                       void *userp)
{
    TRACE_ENTER;
    const char *verstr = "???";
    //   struct Curl_cfilter *cf = userp;
    //   struct Curl_easy *data = NULL;
    char unknown[32];

    //   if(!cf)
    //     return;
    //   data = CF_DATA_CURRENT(cf);
    //   if(!data || !data->set.fdebug || (direction && direction != 1))
    //     return;

    switch (ssl_ver)
    {
#ifdef SSL2_VERSION /* removed in recent versions */
    case SSL2_VERSION:
        verstr = "SSLv2";
        break;
#endif
#ifdef SSL3_VERSION
    case SSL3_VERSION:
        verstr = "SSLv3";
        break;
#endif
    case TLS1_VERSION:
        verstr = "TLSv1.0";
        break;
#ifdef TLS1_1_VERSION
    case TLS1_1_VERSION:
        verstr = "TLSv1.1";
        break;
#endif
#ifdef TLS1_2_VERSION
    case TLS1_2_VERSION:
        verstr = "TLSv1.2";
        break;
#endif
#ifdef TLS1_3_VERSION
    case TLS1_3_VERSION:
        verstr = "TLSv1.3";
        break;
#endif
    case 0:
        break;
    default:
        // msnprintf(unknown, sizeof(unknown), "(%x)", ssl_ver);
        verstr = unknown;
        break;
    }

    /* Log progress for interesting records only (like Handshake or Alert), skip
     * all raw record headers (content_type == SSL3_RT_HEADER or ssl_ver == 0).
     * For TLS 1.3, skip notification of the decrypted inner Content-Type.
     */
    if (ssl_ver
#ifdef SSL3_RT_HEADER
        && content_type != SSL3_RT_HEADER
#endif
#ifdef SSL3_RT_INNER_CONTENT_TYPE
        && content_type != SSL3_RT_INNER_CONTENT_TYPE
#endif
    )
    {
        const char *msg_name, *tls_rt_name;
        // char ssl_buf[1024];
        int msg_type; // txt_len;

        /* the info given when the version is zero is not that useful for us */

        ssl_ver >>= 8; /* check the upper 8 bits only below */

        /* SSLv2 doesn't seem to have TLS record-type headers, so OpenSSL
         * always pass-up content-type as 0. But the interesting message-type
         * is at 'buf[0]'.
         */
        if (ssl_ver == SSL3_VERSION_MAJOR && content_type)
            tls_rt_name = tls_rt_type(content_type);
        else
            tls_rt_name = "";

        if (content_type == SSL3_RT_CHANGE_CIPHER_SPEC)
        {
            msg_type = *(char *)buf;
            msg_name = "Change cipher spec";
        }
        else if (content_type == SSL3_RT_ALERT)
        {
            msg_type = (((char *)buf)[0] << 8) + ((char *)buf)[1];
            msg_name = SSL_alert_desc_string_long(msg_type);
        }
        else
        {
            msg_type = *(char *)buf;
            msg_name = ssl_msg_type(ssl_ver, msg_type);
        }

        // txt_len = msnprintf(ssl_buf, sizeof(ssl_buf),
        //                     "%s (%s), %s, %s (%d):\n",
        printf("=====DEBUG===========\n");
        printf("Version: %s\n", verstr);
        printf("Direction: %s\n", direction ? "OUT" : "IN");
        printf("TLS rt name: %s\n", tls_rt_name);
        printf("Step: %s\n", msg_name);
        // printf("Message type: %s\n", msg_type);
        // if(0 <= txt_len && (unsigned)txt_len < sizeof(ssl_buf)) {
        //   Curl_debug(data, CURLINFO_TEXT, ssl_buf, (size_t)txt_len);
        // }
    }

    //   Curl_debug(data, (direction == 1) ? CURLINFO_SSL_DATA_OUT :
    //              CURLINFO_SSL_DATA_IN, (char *)buf, len);
    (void)ssl;
}

typedef struct
{
    int verbose_mode;
    int verify_depth;
    int always_continue;
} mydata_t;
int mydata_index;

int verify_callback(int isVerifyOk, X509_STORE_CTX *)
{
    TRACE_ENTER;
    if (isVerifyOk)
    {
        printf("====> verify_callback: status: OK\n");
        return 1;
    }
    {
        printf("====> verify_callback: something wrong\n");
        // ERR_print_errors_fp(stderr);
    }
    return isVerifyOk;
}

SSL_CTX *InitCTX(void)
{
    TRACE_ENTER;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                       /* Load cryptos, et.al. */
    SSL_load_error_strings();                           /* Bring in and register error messages */
    const SSL_METHOD *method = TLSv1_2_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method);                          /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // se
    // SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_load_verify_locations(ctx, "./mycert.pem", "./mycert.pem");
    // SSL_CTX_set_post_handshake_auth(ctx, 1);
    // SSL_CTX_set_verify_depth(ctx, 1);
    SSL_CTX_set_msg_callback(ctx, ossl_trace);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    return ctx;
}
void ShowCerts(SSL *ssl)
{
    TRACE_ENTER;
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        BIO *b = BIO_new(BIO_s_file());
        BIO_set_fp(b, stdout, BIO_NOCLOSE);
        X509_print(b, cert);
        free(line);      /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
void printOpenSSLError()
{
    TRACE_ENTER;
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    /*size_t len = */ BIO_get_mem_data(bio, &buf);
    printf("SSL Error: %s\n", buf);
    BIO_free(bio);
}

SSL *setupSSL(SSL_CTX *ctx, int fd)
{
    TRACE_ENTER;
    SSL *ssl = SSL_new(ctx); /* create new SSL connection sta  te */
    if (!ssl)
    {
        printf("Couldn't SSL_new\n");
    }
    SSL_set_connect_state(ssl);
    (void)SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    if (SSL_set_fd(ssl, fd)) /* attach the socket descriptor */
    {
        printf("Could not SSL_set_fd\n");
    }
    return ssl;
}

int initSSL()

{
    TRACE_ENTER;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    !defined(LIBRESSL_VERSION_NUMBER)
    const uint64_t flags =
#ifdef OPENSSL_INIT_ENGINE_ALL_BUILTIN
        /* not present in BoringSSL */
        OPENSSL_INIT_ENGINE_ALL_BUILTIN |
#endif
    OPENSSL_INIT_LOAD_CONFIG;

    OPENSSL_init_ssl(flags, NULL);
    OPENSSL_load_builtin_modules();

    /* Let's get nice error messages */
    SSL_load_error_strings();

    /* Init the global ciphers and digests */
    if (!SSLeay_add_ssl_algorithms())
    {
        return 0;
    }
    OpenSSL_add_all_algorithms();
    return 1;
#endif
}
int main(int count, char *strings[])
{
    TRACE_ENTER;
    if(!initSSL())
    {
        printf("Init openssl failed!!!!\n");
    }
    SSL_CTX *ctx;
    int socketFd;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes;
    char *hostname, *portnum;
    if (count != 3)
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    printf("Prepare SSL_library_init()\n");
    SSL_library_init();
    hostname = strings[1];
    portnum = strings[2];
    printf("Prepare InitCTX()\n");
    ctx = InitCTX();
    socketFd = OpenConnection(hostname, atoi(portnum));
    SSL *ssl = setupSSL(ctx, socketFd);
    if (SSL_connect(ssl) == FAIL) /* perform the connection */
    {
        // printOpenSSLError();
        long lerr = SSL_get_verify_result(ssl);
        if (lerr != X509_V_OK)
        {
            printf("SSL certificate problem: %s\n",
                   X509_verify_cert_error_string(lerr));
        }
        ERR_print_errors_fp(stderr);
    }
    else
    {
        // if (SSL_do_handshake(ssl) <= 0)
        // {
        //     printf("VERIFY FAILURE");
        //     ERR_print_errors_fp(stderr);
        // }
        // else
        // {
        //     if (SSL_connect(ssl) == FAIL) /* perform the connection */
        //     {
        //         printOpenSSLError();
        //         ERR_print_errors_fp(stderr);
        //         return 1;
        //     }
        // printf("VERIFY SUCCESS");

        // char acUsername[16] = {0};
        // char acPassword[16] = {0};
        // const char *cpRequestMessage = "<Body>"
        //                                "<UserName>%s<UserName>"
        //                                "<Password>%s<Password>"
        //                                "<\\Body>";
        // printf("Enter the User Name : ");
        // scanf("%s", acUsername);
        // printf("\n\nEnter the Password : ");
        // scanf("%s", acPassword);
        // sprintf(acClientRequest, cpRequestMessage, acUsername, acPassword); /* construct reply */

        // printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);                                           /* get any certs */
        SSL_write(ssl, acClientRequest, strlen(acClientRequest)); /* encrypt & send message */
        // bytes = SSL_read(ssl, buf, sizeof(buf));                  /* get reply & decrypt */
        // buf[bytes] = 0;
        // printf("Received: \"%s\"\n", buf);
        SSL_free(ssl); /* release connection state */
    }
    close(socketFd);   /* close socket */
    SSL_CTX_free(ctx); /* release context */
    SSL_free(ssl);
    return 0;
}
