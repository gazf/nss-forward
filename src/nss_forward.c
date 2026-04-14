/*
 * nss_forward.c — LD_PRELOAD library for musl/Alpine
 *
 * Overrides getpwnam/getpwuid/getgrnam/getgrgid and their _r variants.
 * Makes an HTTP GET to NSS_PROXY_URL and parses the passwd/group line.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o libnss_forward.so nss_forward.c
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* HTTP client                                                          */
/* ------------------------------------------------------------------ */

#define HTTP_BUF 4096

/*
 * Perform HTTP GET <path> against the host:port extracted from base_url.
 * Returns body length on success, -1 on error.
 * buf must be at least HTTP_BUF bytes.
 *
 * When NSS_FORWARD_TESTING is defined this function is omitted so the
 * test translation unit can supply its own mock instead.
 */
#ifndef NSS_FORWARD_TESTING
static int http_get(const char *base_url, const char *path,
                    char *buf, size_t buf_len)
{
    /* Parse base_url: http://host[:port] */
    if (strncmp(base_url, "http://", 7) != 0)
        return -1;

    char hostbuf[256];
    char portbuf[16];
    const char *after = base_url + 7;

    /* Strip trailing slash */
    const char *slash = strchr(after, '/');
    size_t hostpart_len = slash ? (size_t)(slash - after) : strlen(after);
    if (hostpart_len >= sizeof(hostbuf))
        return -1;
    memcpy(hostbuf, after, hostpart_len);
    hostbuf[hostpart_len] = '\0';

    const char *colon = strchr(hostbuf, ':');
    if (colon) {
        snprintf(portbuf, sizeof(portbuf), "%s", colon + 1);
        hostbuf[colon - hostbuf] = '\0';
    } else {
        snprintf(portbuf, sizeof(portbuf), "80");
    }

    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                               .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(hostbuf, portbuf, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    /* Send request */
    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, hostbuf);
    if (send(fd, req, req_len, 0) != req_len) {
        close(fd);
        return -1;
    }

    /* Receive response */
    char raw[HTTP_BUF * 2];
    int total = 0;
    int n;
    while ((n = recv(fd, raw + total, sizeof(raw) - 1 - total, 0)) > 0)
        total += n;
    close(fd);
    raw[total] = '\0';

    /* Check status 200 */
    if (strncmp(raw, "HTTP/", 5) != 0) return -1;
    char *sp = strchr(raw, ' ');
    if (!sp || atoi(sp + 1) != 200) return -1;

    /* Extract body (after \r\n\r\n) */
    char *body = strstr(raw, "\r\n\r\n");
    if (!body) return -1;
    body += 4;

    size_t blen = strlen(body);
    if (blen >= buf_len) blen = buf_len - 1;
    memcpy(buf, body, blen);
    buf[blen] = '\0';

    /* Strip trailing newline */
    while (blen > 0 && (buf[blen-1] == '\n' || buf[blen-1] == '\r'))
        buf[--blen] = '\0';

    return (int)blen;
}
#endif /* NSS_FORWARD_TESTING */

/* ------------------------------------------------------------------ */
/* passwd line parser: user:x:uid:gid:gecos:home:shell                 */
/* ------------------------------------------------------------------ */

static int parse_passwd(char *line, struct passwd *pw, char *buf, size_t buflen)
{
    /* Copy line into buf for strsep in-place modification */
    size_t llen = strlen(line);
    if (llen + 1 > buflen) return -1;
    memcpy(buf, line, llen + 1);

    char *p = buf;
    char *fields[7];
    for (int i = 0; i < 7; i++) {
        fields[i] = strsep(&p, ":");
        if (!fields[i]) return -1;
    }

    pw->pw_name   = fields[0];
    pw->pw_passwd = fields[1];
    pw->pw_uid    = (uid_t)atol(fields[2]);
    pw->pw_gid    = (gid_t)atol(fields[3]);
    pw->pw_gecos  = fields[4];
    pw->pw_dir    = fields[5];
    pw->pw_shell  = fields[6];
    return 0;
}

/* ------------------------------------------------------------------ */
/* group line parser: name:x:gid:mem1,mem2,...                         */
/* ------------------------------------------------------------------ */

#define MAX_MEMBERS 64

static int parse_group(char *line, struct group *gr,
                        char *buf, size_t buflen,
                        char **membuf, size_t membuf_len)
{
    size_t llen = strlen(line);
    if (llen + 1 > buflen) return -1;
    memcpy(buf, line, llen + 1);

    char *p = buf;
    char *fields[4];
    for (int i = 0; i < 4; i++) {
        fields[i] = strsep(&p, ":");
        if (!fields[i]) {
            if (i == 3) fields[i] = "";
            else return -1;
        }
    }

    gr->gr_name   = fields[0];
    gr->gr_passwd = fields[1];
    gr->gr_gid    = (gid_t)atol(fields[2]);

    /* Parse comma-separated members into membuf */
    static char *members[MAX_MEMBERS + 1];
    int nmem = 0;
    char *members_str = fields[3];
    char *mem;
    while ((mem = strsep(&members_str, ",")) && nmem < MAX_MEMBERS) {
        if (*mem) members[nmem++] = mem;
    }
    members[nmem] = NULL;
    gr->gr_mem = members;
    (void)membuf; (void)membuf_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static const char *proxy_url(void)
{
    const char *url = getenv("NSS_PROXY_URL");
    return url ? url : "http://nss-proxy:8080";
}

/* Thread-local storage for non-_r variants */
static __thread char pw_buf[4096];
static __thread struct passwd pw_result;
static __thread char gr_buf[4096];
static __thread struct group  gr_result;

static char http_body[HTTP_BUF];

/* ------------------------------------------------------------------ */
/* getpwnam / getpwnam_r                                               */
/* ------------------------------------------------------------------ */

struct passwd *getpwnam(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "/passwd/%s", name);
    if (http_get(proxy_url(), path, http_body, sizeof(http_body)) < 0)
        return NULL;
    if (parse_passwd(http_body, &pw_result, pw_buf, sizeof(pw_buf)) < 0)
        return NULL;
    return &pw_result;
}

int getpwnam_r(const char *name, struct passwd *pwd,
               char *buf, size_t buflen, struct passwd **result)
{
    char path[256];
    snprintf(path, sizeof(path), "/passwd/%s", name);
    char body[HTTP_BUF];
    if (http_get(proxy_url(), path, body, sizeof(body)) < 0) {
        *result = NULL; return ENOENT;
    }
    if (parse_passwd(body, pwd, buf, buflen) < 0) {
        *result = NULL; return ERANGE;
    }
    *result = pwd;
    return 0;
}

/* ------------------------------------------------------------------ */
/* getpwuid / getpwuid_r                                               */
/* ------------------------------------------------------------------ */

struct passwd *getpwuid(uid_t uid)
{
    char path[256];
    snprintf(path, sizeof(path), "/passwd/uid/%lu", (unsigned long)uid);
    if (http_get(proxy_url(), path, http_body, sizeof(http_body)) < 0)
        return NULL;
    if (parse_passwd(http_body, &pw_result, pw_buf, sizeof(pw_buf)) < 0)
        return NULL;
    return &pw_result;
}

int getpwuid_r(uid_t uid, struct passwd *pwd,
               char *buf, size_t buflen, struct passwd **result)
{
    char path[256];
    snprintf(path, sizeof(path), "/passwd/uid/%lu", (unsigned long)uid);
    char body[HTTP_BUF];
    if (http_get(proxy_url(), path, body, sizeof(body)) < 0) {
        *result = NULL; return ENOENT;
    }
    if (parse_passwd(body, pwd, buf, buflen) < 0) {
        *result = NULL; return ERANGE;
    }
    *result = pwd;
    return 0;
}

/* ------------------------------------------------------------------ */
/* getgrnam / getgrnam_r                                               */
/* ------------------------------------------------------------------ */

struct group *getgrnam(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "/group/%s", name);
    if (http_get(proxy_url(), path, http_body, sizeof(http_body)) < 0)
        return NULL;
    if (parse_group(http_body, &gr_result, gr_buf, sizeof(gr_buf), NULL, 0) < 0)
        return NULL;
    return &gr_result;
}

int getgrnam_r(const char *name, struct group *grp,
               char *buf, size_t buflen, struct group **result)
{
    char path[256];
    snprintf(path, sizeof(path), "/group/%s", name);
    char body[HTTP_BUF];
    if (http_get(proxy_url(), path, body, sizeof(body)) < 0) {
        *result = NULL; return ENOENT;
    }
    if (parse_group(body, grp, buf, buflen, NULL, 0) < 0) {
        *result = NULL; return ERANGE;
    }
    *result = grp;
    return 0;
}

/* ------------------------------------------------------------------ */
/* getgrgid / getgrgid_r                                               */
/* ------------------------------------------------------------------ */

struct group *getgrgid(gid_t gid)
{
    char path[256];
    snprintf(path, sizeof(path), "/group/gid/%lu", (unsigned long)gid);
    if (http_get(proxy_url(), path, http_body, sizeof(http_body)) < 0)
        return NULL;
    if (parse_group(http_body, &gr_result, gr_buf, sizeof(gr_buf), NULL, 0) < 0)
        return NULL;
    return &gr_result;
}

int getgrgid_r(gid_t gid, struct group *grp,
               char *buf, size_t buflen, struct group **result)
{
    char path[256];
    snprintf(path, sizeof(path), "/group/gid/%lu", (unsigned long)gid);
    char body[HTTP_BUF];
    if (http_get(proxy_url(), path, body, sizeof(body)) < 0) {
        *result = NULL; return ENOENT;
    }
    if (parse_group(body, grp, buf, buflen, NULL, 0) < 0) {
        *result = NULL; return ERANGE;
    }
    *result = grp;
    return 0;
}
