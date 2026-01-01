/*
 * Copyright 2025 Patrik Schindler <poc@pocnet.net>.
 *
 * This file is part of chkhibpwnd, an application to query the Have I Been
 * Pwned API if a password has been leaked.
 *
 * Licensing terms.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this; if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 * Suite 330, Boston, MA  02111-1307  USA or get it at
 * http://www.gnu.org/licenses/gpl.html
 *
 * This C application uses only standard C library functions to talk to the
 * api.pwnedpasswords.com API server. This makes it easy to compile the program
 * even on older operating systems. Unfortunately, the API server refuses plain
 * text connections on port 80, and implementing TLS completely seems a bit over
 * the top. Hence we rely on the http_proxy (or HTTP_PROXY) environment variable
 * to provide a http proxy which terminates the TLS session on our behalf.
 *
 * Currently the code has been tested on Linux and stone age OS/400 V4R5.
 * OS/400 specific stuff is automatically recognized by the __ILEC400__ macro.
 * It is set by the ILE C compiler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

/* FIXME: Come up with an unified method of providing textual information to
 * the user, in turn retaining contextual information. Expand sendMsg?
 */

#ifdef __ILEC400__
/* OS/400 specific defines. */
#pragma nomargins                        /* No positional restrictions. */

typedef unsigned int uint32_t;

#include <qusec.h>                       /* Qus_EC_t */
#include <qmhsndpm.h>                    /* QMHSNDPM */
#include <qtqiconv.h>                    /* EBCDIC <=> ASCII conversion */
#if __ILEC400_TGTVRM__ >= 430
#include <qp0ztrc.h>                     /* Qp0zLprintf() */
#else
int  Qp0zLprintf (char *format, ...);    /* Not officially included in V3R2 */
#endif
#define ssprintf Qp0zLprintf             /* Write to job log. */

#else

/* For Linux and other unix lookalikes. */
#include <stdint.h>

#define ssprintf printf                  /* Write to stdout. */

#endif

/*------------------------------------------------------------------------------
 * Defines and global vars.
 *
 * Socket related constants
 */
#define HIBP_HOST "api.pwnedpasswords.com"
#define RESPONSE_SIZE 1048576
#define REQUEST_SIZE 256

/* Global variables, so we can easily iconv anywhere in our code. */
#ifdef __ILEC400__
iconv_t a_e_ccsid;
iconv_t e_a_ccsid;
#endif

/*------------------------------------------------------------------------------
 * SHA-1 implementation - RFC 3174.
 *
 * FIXME: Starting with V5R3, this could be delegted to the Calculate Hash API,
 * (QC3CALHA, Qc3CalculateHash). Possibly use the __ILEC400_VRM__ macro to check
 * for availability?
 */

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

struct SHA1_CTX {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
};

void SHA1_Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t temp;
    uint32_t W[80];
    int t;


    /* Initialize the first 16 words. */
    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t) buffer[t * 4] << 24)
            | ((uint32_t) buffer[t * 4 + 1] << 16)
            | ((uint32_t) buffer[t * 4 + 2] << 8)
            | ((uint32_t) buffer[t * 4 + 3]);
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words. */
    for (t = 16; t < 80; t++) {
        W[t] = rol(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Main loop. */
    for (t = 0; t < 80; t++) {
        if (t < 20) {
            temp = ((b & c) | ((~b) & d)) + 0x5A827999;
        } else if (t < 40) {
            temp = (b ^ c ^ d) + 0x6ED9EBA1;
        } else if (t < 60) {
            temp = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
        } else {
            temp = (b ^ c ^ d) + 0xCA62C1D6;
        }

        temp += rol(a, 5) + e + W[t];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1_Init(struct SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = 0;
    context->count[1] = 0;
}

void SHA1_Update(struct SHA1_CTX *context, const unsigned char *data,
        uint32_t len) {
    uint32_t i, j;


    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) {
        context->count[1]++;
    }
    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&context->buffer[j], data, i);
        SHA1_Transform(context->state, context->buffer);

        for (; i + 63 < len; i += 64) {
            SHA1_Transform(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1_Final(unsigned char digest[20], struct SHA1_CTX *context) {
    unsigned char finalcount[8];
    unsigned char c;
    int i;


    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
                >> ((3 - (i & 3)) * 8)) & 255);
    }
    c = 0x80;
    SHA1_Update(context, &c, 1);

    while ((context->count[0] & 504) != 448) {
        c = 0;
        SHA1_Update(context, &c, 1);
    }
    SHA1_Update(context, finalcount, 8);

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] =
            (unsigned char)((context->state[i >> 2] >> ((3 -
                        (i & 3)) * 8)) & 255);
    }
}

/*------------------------------------------------------------------------------
 * Function to convert binary hash to hex string.
 */

void bin2hex(unsigned char *bin, char *hex, int len) {
    static const char hex_chars[] = "0123456789ABCDEF";
    int i;


    for (i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[bin[i] >> 4];
        hex[i * 2 + 1] = hex_chars[bin[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

#ifdef __ILEC400__

/*------------------------------------------------------------------------------
 * Zero-terminate fixed-length strings.
 */

/* Note: This code assumes that we always have at least one position left
 *       to properly zero-terminate the string! Ugly but spares us the need
 *       to copy the data to a bigger buffer beforehand.
 * Note: This code changes data in the original buffer!
 */

char *fixstr(char *buf, int length) {
    int i;


    /* Iterate through the buffer from right to left, and set position next to
     * the first non-blank to NUL. */
    for (i = (length - 1); i >= 0; i--) {
        if (buf[i] != ' ') {
            buf[i + 1] = 0x0;
            break;
        }
    }

    return(buf);
}

/*------------------------------------------------------------------------------
 * Send a message.
 */

int sendMsg(char *pMsgData) {
    char MSGKey[4];
    Qus_EC_t errorCode;


    memset(&errorCode, 0, sizeof(errorCode));
    errorCode.Bytes_Provided = sizeof(errorCode);

    QMHSNDPM("CPF9897"                   /* Message identifier */
        , "QCPFMSG   *LIBL     "         /* Qualified message file name */
        , pMsgData                       /* Replacement data */
        , strlen(pMsgData)               /* Length of replacement data */
        , "*COMP     "                   /* message type */
        , "*PGMBDY   "                   /* call stack entry to send the */
                                         /* message */
        , 1                              /* message queue number */
        , MSGKey                         /* message key */
        , &errorCode                     /* Error code feedback */
    );

    if (errorCode.Bytes_Available) {
        ssprintf("sendMsg() - QMHSNDPM API return error='%0.7s'",
            errorCode.Exception_Id);
        return(1);
    }

    return (0);
}

/*------------------------------------------------------------------------------
 * Charset conversion.
 */

int convert_buffer(char *srcBuf, char *dstBuf, int srcBufLen, int dstBufLen,
        iconv_t table) {
    int retval = 0;
    size_t srcsz;
    size_t dstsz;
    char *dst_buf;
    char *src_buf;


    srcsz = srcBufLen;
    dstsz = dstBufLen;
    src_buf = srcBuf;
    dst_buf = dstBuf;
    retval = (iconv(table, (char **)&(src_buf), &srcsz, (char **)&(dst_buf),
            &dstsz));

    return(retval);
}
#endif

/*------------------------------------------------------------------------------
 * HTTP proxy host/port parsing from http_proxy variable.
 */

int parse_proxy_env(char **out_host, int *out_port) {
    char numbuf[8], *p, *host_start, *host_end, *port_start, *port_end, *at,
        *env;
    int port = 0;
    size_t n, host_len;


#ifdef __ILEC400__
    /* Envvars are UPPER CASE in OS/400. */
    env = getenv("HTTP_PROXY");
#else
    env = getenv("http_proxy");
#endif
    if (!env || strlen(env) == 0) {
        ssprintf("Error: HTTP_PROXY environment variable not set.\n");
        return (-1);
    }

    p = env;
    /* Skip URI scheme if present. */
    if ((strncmp(p, "http://", 7) == 0) || (strncmp(p, "HTTP://", 7) == 0)) {
        p += 7;
    }

    /* Support optional username:password@; skip up to '@' if present. */
    host_start = p;
    at = strchr(host_start, '@');

    if (at) {
        host_start = at + 1;
    }

    /* Find ':' for port, or '/' or '\0' */
    host_end = host_start;
    while (*host_end && *host_end != ':' && *host_end != '/') {
        host_end++;
    }
    host_len = host_end - host_start;
    if (host_len == 0 || host_len > 255) {
        ssprintf("Error: Malformed http_proxy (host missing or too long).\n");
        return (-1);
    }

    *out_host = malloc(host_len + 1);
    if (!*out_host) {
        /* FIXME: Job Log! */
        perror("malloc");
        return (-1);
    }
    memcpy(*out_host, host_start, host_len);
    (*out_host)[host_len] = '\0';

    /* Check for port. */
    port_start = NULL;
    if (*host_end == ':') {
        port_start = host_end + 1;
        port_end = port_start;

        while (*port_end && isdigit((unsigned char)*port_end)) {
            port_end++;
        }
        if (port_end == port_start) {
            ssprintf("Error: Malformed http_proxy (port missing).\n");
            free(*out_host);
            return (-1);
        }
        n = port_end - port_start;

        if (n > sizeof(numbuf) - 1)
            n = sizeof(numbuf) - 1;
        memcpy(numbuf, port_start, n);
        numbuf[n] = '\0';
        port = atoi(numbuf);
        if (port < 1 || port > 65535) {
            ssprintf("Error: Malformed http_proxy (port out of range).\n");
            free(*out_host);
            return (-1);
        }
    } else {
        /* Default port 80 for HTTP. */
        port = 80;
    }

    *out_port = port;

    return (0);
}

/*------------------------------------------------------------------------------
 * Socket based HTTP GET implementation.
 */

int http_get(const char *prefix, char *response, size_t response_size,
        const char *proxy_host, int proxy_port) {
#ifdef __ILEC400__
    char request_ascii[REQUEST_SIZE];
#endif
    char request[REQUEST_SIZE], response_ascii[RESPONSE_SIZE], buffer[1024],
        *body;
    struct sockaddr_in server_addr;
    struct hostent *server;
    int total = 0, bytes_received, sockfd;


    /* Prepare HTTP request. */
    sprintf(request, "GET https://%s/range/%s HTTP/1.0\r\n" "Host: %s\r\n"
        "User-Agent: C89-HIBP-Client/1.0\r\n" "Connection: close\r\n" "\r\n",
        HIBP_HOST, prefix, HIBP_HOST);

#ifdef __ILEC400__
    convert_buffer(request, request_ascii, strlen(request), strlen(request),
        e_a_ccsid);
#endif

    /* Create socket. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        /* FIXME: Job Log! */
        perror("Error creating socket");
        return (-1);
    }

    /* Get host info. */
#ifdef __ILEC400__
    server = gethostbyname((unsigned char *)proxy_host);
#else
    server = gethostbyname(proxy_host);
#endif
    if (server == NULL) {
        ssprintf("Error: Could not resolve proxy host %s.\n", proxy_host);
        close(sockfd);
        return (1);
    }

    /* Prepare the server address structure. */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(proxy_port);

    /* Connect to the server. */
    if (connect(sockfd, (struct sockaddr *)&server_addr,
            sizeof(server_addr)) < 0) {
        /* FIXME: Job Log! */
        perror("Error connecting to proxy server");
        close(sockfd);
        return (-1);
    }

    /* Send request. */
#ifdef __ILEC400__
    if (send(sockfd, request_ascii, strlen(request_ascii), 0) < 0) {
        /* FIXME: Job Log! */
        perror("Error sending request");
        close(sockfd);
        return (-1);
    }
#else
    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("Error sending request");
        close(sockfd);
        return (-1);
    }
#endif

    /* Clear response buffer. */
    memset(response_ascii, 0, response_size);

    /* Read response. */
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        if (total + bytes_received >= response_size) {
            bytes_received = response_size - total - 1;
            if (bytes_received <= 0)
                break;
        }
        memcpy(response_ascii + total, buffer, bytes_received);
        total += bytes_received;
        response_ascii[total] = '\0';
    }

#ifdef __ILEC400__
    /* Convert ASCII back to EBCDIC on OS/400. Otherwise copy buffer. */
    convert_buffer(response_ascii, response, strlen(response_ascii),
        strlen(response_ascii), a_e_ccsid);
#else
    memcpy(response, response_ascii, total);
#endif

    /* Clean up. */
    close(sockfd);

    if (bytes_received < 0) {
        /* FIXME: Job Log! */
        perror("Error receiving response");
        return (-1);
    }

    /* Skip HTTP headers to get to body.  */
    body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;                       /* Skip the \r\n\r\n. */
        memmove(response, body, strlen(body) + 1);
    }

    return (0);
}

/*------------------------------------------------------------------------------
 * Main.
 */

int main(int argc, char *argv[]) {
    struct SHA1_CTX ctx;
    unsigned char hash[SHA1_DIGEST_SIZE];
    char hex_hash[41];                   /* 40 chars + NULL terminator. */
    char prefix[6];                      /* First 5 chars + null terminator. */
    char response[RESPONSE_SIZE];
    char *arg_ascii = NULL, *suffix, *proxy_host = NULL;
    int found = 0, proxy_port = 0;
    size_t arg_len = 0;


#ifdef __ILEC400__
    QtqCode_T jobCode = { 0, 0, 0, 0, 0, 0 };
    QtqCode_T asciiCode = { 819, 0, 0, 0, 0, 0 };
#endif

    /* Parse env for proxy. */
    if (parse_proxy_env(&proxy_host, &proxy_port) != 0) {
        return (2);
    }

#ifdef __ILEC400__
    /* When we use OS/400 command prompting, we need to remove excess blanks. */
    fixstr(argv[1], strlen(argv[1]));
#else
    /* This is already verified by the CMD. */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        free(proxy_host);
        return (1);
    }
#endif

    /* We need this later repeatedly. */
    arg_len = strlen(argv[1]);

#ifdef __ILEC400__
    /* Create the conversion tables. These are used in the http handler. */
    /* ASCII to EBCDIC. */
    a_e_ccsid = QtqIconvOpen(&jobCode, &asciiCode);
    if (a_e_ccsid.return_value == -1) {
        iconv_close(a_e_ccsid);
        Qp0zLprintf("Warning: QtqIconvOpen failed.");
    }

    /* EBCDIC to ASCII. */
    e_a_ccsid = QtqIconvOpen(&asciiCode, &jobCode);
    if (e_a_ccsid.return_value == -1) {
        iconv_close(e_a_ccsid);
        Qp0zLprintf("Warning: QtqIconvOpen failed.");
    }

    /* Convert password from EBDIC to ASCII on OS/400 to match hash values. */
    arg_ascii = malloc(arg_len + 1);
    convert_buffer(argv[1], arg_ascii, arg_len, arg_len, e_a_ccsid);
#else
    arg_ascii = argv[1];
#endif

    /* Calculate SHA-1 hash. */
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char *)arg_ascii, arg_len);
    SHA1_Final(hash, &ctx);

#ifdef __ILEC400__
    free(arg_ascii);
#endif

    /* Convert to hex string. */
    bin2hex(hash, hex_hash, SHA1_DIGEST_SIZE);

    /* Split hash into prefix and suffix. */
    strncpy(prefix, hex_hash, 5);
    prefix[5] = '\0';
    suffix = hex_hash + 5;

    /* Query API. EBCDIC/ASCII conversion on OS/400 is done in http_get(). */
    if (http_get(prefix, response, sizeof(response), proxy_host,
            proxy_port) != 0) {
        ssprintf("Failed to query API.\n");
        free(proxy_host);
        return (1);
    }
    free(proxy_host);

    /* Check if hash suffix exists in response. */
    found = (strstr(response, suffix) != NULL);

    /* Output result. */
#ifdef __ILEC400__
    /* Show result in msgline. */
    if (found) {
        sendMsg("Password has been pwned.");
    } else {
        sendMsg("Password not found in database.");
    }
#else
    if (found) {
        ssprintf("Password has been pwned.\n");
    } else {
        ssprintf("Password not found in database.\n");
    }
#endif

    return (0);
}

/*------------------------------------------------------------------------------
 * vim: ft=c colorcolumn=81 autoindent shiftwidth=4 tabstop=4 expandtab
 */
