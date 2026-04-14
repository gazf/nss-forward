/*
 * nss_forward_test.c
 *
 * モック http_get を差し込んで getpwnam/getpwuid/getgrnam/getgrgid と
 * それぞれの _r 変種のパース・ルーティングを検証する。
 *
 * Build & run:
 *   gcc -DNSS_FORWARD_TESTING -o nss_forward_test nss_forward_test.c && ./nss_forward_test
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

/* ------------------------------------------------------------------ */
/* モック http_get                                                      */
/* ------------------------------------------------------------------ */

/*
 * テスト用の固定レスポンスを path に応じて返す。
 * 実際のネットワーク呼び出しは一切行わない。
 */
/* 1 にセットすると全リクエストでネットワークエラー (-1) を返す */
static int mock_network_error = 0;

static int http_get(const char *base_url, const char *path,
                    char *buf, size_t buf_len)
{
    (void)base_url;
    if (mock_network_error) return -1;
    const char *body = NULL;

    if (strcmp(path, "/passwd/alice") == 0)
        body = "alice:x:1001:100:Alice Smith:/home/alice:/bin/bash";
    else if (strcmp(path, "/passwd/uid/1001") == 0)
        body = "alice:x:1001:100:Alice Smith:/home/alice:/bin/bash";
    else if (strcmp(path, "/passwd/minimal") == 0)
        /* gecos・home・shell が空のエントリ */
        body = "minimal:x:9999:0:::";
    else if (strcmp(path, "/group/staff") == 0)
        body = "staff:x:100:alice,bob,carol";
    else if (strcmp(path, "/group/gid/100") == 0)
        body = "staff:x:100:alice,bob,carol";
    else if (strcmp(path, "/group/empty") == 0)
        body = "empty:x:200:";
    /* それ以外は 404 */

    if (!body) return 404;
    size_t len = strlen(body);
    if (len >= buf_len) return -1;
    memcpy(buf, body, len + 1);
    return 200;
}

/* ------------------------------------------------------------------ */
/* テスト対象コードをインクルード                                       */
/* ------------------------------------------------------------------ */

#include "../src/nss_forward.c"

/* ------------------------------------------------------------------ */
/* 軽量テストハーネス                                                   */
/* ------------------------------------------------------------------ */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { \
        printf("  PASS  %s\n", msg); \
        g_pass++; \
    } else { \
        printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        g_fail++; \
    } \
} while (0)

/* ------------------------------------------------------------------ */
/* テストケース                                                         */
/* ------------------------------------------------------------------ */

/*
 * 404 またはネットワークエラー (-1) のときフォールバック関数が呼ばれることを検証する。
 * テストモードの fallback は nss_forward_fallback_count をインクリメントして
 * NULL / ENOENT を返すスタブ。実運用では dlsym(RTLD_NEXT) が /etc/passwd を読む。
 */
extern int nss_forward_fallback_count;

static void test_fallback(void)
{
    puts("フォールバック (404)");

    struct passwd pw;
    char buf[1024];
    struct passwd *result;
    struct group  gr;
    struct group  *grp;

    nss_forward_fallback_count = 0;
    getpwnam("nobody");
    CHECK(nss_forward_fallback_count == 1, "getpwnam: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwuid(0);
    CHECK(nss_forward_fallback_count == 1, "getpwuid: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwnam_r("nobody", &pw, buf, sizeof(buf), &result);
    CHECK(nss_forward_fallback_count == 1, "getpwnam_r: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwuid_r(0, &pw, buf, sizeof(buf), &result);
    CHECK(nss_forward_fallback_count == 1, "getpwuid_r: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrnam("root");
    CHECK(nss_forward_fallback_count == 1, "getgrnam: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrgid(0);
    CHECK(nss_forward_fallback_count == 1, "getgrgid: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrnam_r("root", &gr, buf, sizeof(buf), &grp);
    CHECK(nss_forward_fallback_count == 1, "getgrnam_r: 404 で fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrgid_r(0, &gr, buf, sizeof(buf), &grp);
    CHECK(nss_forward_fallback_count == 1, "getgrgid_r: 404 で fallback 呼び出し");

    puts("フォールバック (ネットワークエラー)");

    mock_network_error = 1;

    nss_forward_fallback_count = 0;
    getpwnam("alice");
    CHECK(nss_forward_fallback_count == 1, "getpwnam: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwuid(1001);
    CHECK(nss_forward_fallback_count == 1, "getpwuid: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwnam_r("alice", &pw, buf, sizeof(buf), &result);
    CHECK(nss_forward_fallback_count == 1, "getpwnam_r: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getpwuid_r(1001, &pw, buf, sizeof(buf), &result);
    CHECK(nss_forward_fallback_count == 1, "getpwuid_r: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrnam("staff");
    CHECK(nss_forward_fallback_count == 1, "getgrnam: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrgid(100);
    CHECK(nss_forward_fallback_count == 1, "getgrgid: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrnam_r("staff", &gr, buf, sizeof(buf), &grp);
    CHECK(nss_forward_fallback_count == 1, "getgrnam_r: ネットワークエラーで fallback 呼び出し");

    nss_forward_fallback_count = 0;
    getgrgid_r(100, &gr, buf, sizeof(buf), &grp);
    CHECK(nss_forward_fallback_count == 1, "getgrgid_r: ネットワークエラーで fallback 呼び出し");

    mock_network_error = 0;
}

static void test_getpwnam(void)
{
    puts("getpwnam");

    struct passwd *pw = getpwnam("alice");
    CHECK(pw != NULL,                    "alice が見つかる");
    CHECK(strcmp(pw->pw_name,   "alice")         == 0, "pw_name");
    CHECK(strcmp(pw->pw_passwd, "x")             == 0, "pw_passwd は x");
    CHECK(pw->pw_uid == 1001,                          "pw_uid");
    CHECK(pw->pw_gid == 100,                           "pw_gid");
    CHECK(strcmp(pw->pw_gecos,  "Alice Smith")   == 0, "pw_gecos");
    CHECK(strcmp(pw->pw_dir,    "/home/alice")   == 0, "pw_dir");
    CHECK(strcmp(pw->pw_shell,  "/bin/bash")     == 0, "pw_shell");

    struct passwd *pw2 = getpwnam("nobody");
    CHECK(pw2 == NULL, "存在しないユーザーは NULL");
}

static void test_getpwuid(void)
{
    puts("getpwuid");

    struct passwd *pw = getpwuid(1001);
    CHECK(pw != NULL,                    "uid=1001 が見つかる");
    CHECK(strcmp(pw->pw_name, "alice") == 0, "pw_name");
    CHECK(pw->pw_uid == 1001,                "pw_uid");

    struct passwd *pw2 = getpwuid(9999);
    CHECK(pw2 == NULL, "存在しない uid は NULL");
}

static void test_getpwnam_r(void)
{
    puts("getpwnam_r");

    struct passwd pw;
    char buf[1024];
    struct passwd *result;

    int ret = getpwnam_r("alice", &pw, buf, sizeof(buf), &result);
    CHECK(ret == 0,                          "返値 0");
    CHECK(result == &pw,                     "result が pw を指す");
    CHECK(strcmp(pw.pw_name, "alice") == 0,  "pw_name");
    CHECK(pw.pw_uid == 1001,                 "pw_uid");

    ret = getpwnam_r("nobody", &pw, buf, sizeof(buf), &result);
    CHECK(ret == ENOENT, "存在しないユーザーは ENOENT");
    CHECK(result == NULL, "result が NULL");
}

static void test_getpwuid_r(void)
{
    puts("getpwuid_r");

    struct passwd pw;
    char buf[1024];
    struct passwd *result;

    int ret = getpwuid_r(1001, &pw, buf, sizeof(buf), &result);
    CHECK(ret == 0,         "返値 0");
    CHECK(result != NULL,   "result が非 NULL");
    CHECK(pw.pw_uid == 1001, "pw_uid");

    ret = getpwuid_r(9999, &pw, buf, sizeof(buf), &result);
    CHECK(ret == ENOENT, "存在しない uid は ENOENT");
    CHECK(result == NULL, "result が NULL");
}

static void test_getgrnam(void)
{
    puts("getgrnam");

    struct group *gr = getgrnam("staff");
    CHECK(gr != NULL,                      "staff が見つかる");
    CHECK(strcmp(gr->gr_name, "staff") == 0, "gr_name");
    CHECK(strcmp(gr->gr_passwd, "x") == 0,   "gr_passwd は x");
    CHECK(gr->gr_gid == 100,                 "gr_gid");
    CHECK(gr->gr_mem != NULL,                "gr_mem が非 NULL");
    CHECK(strcmp(gr->gr_mem[0], "alice") == 0, "メンバー[0] alice");
    CHECK(strcmp(gr->gr_mem[1], "bob")   == 0, "メンバー[1] bob");
    CHECK(strcmp(gr->gr_mem[2], "carol") == 0, "メンバー[2] carol");
    CHECK(gr->gr_mem[3] == NULL,               "メンバーリスト終端 NULL");

    struct group *gr2 = getgrnam("ghost");
    CHECK(gr2 == NULL, "存在しないグループは NULL");
}

static void test_getgrgid(void)
{
    puts("getgrgid");

    struct group *gr = getgrgid(100);
    CHECK(gr != NULL,                        "gid=100 が見つかる");
    CHECK(strcmp(gr->gr_name, "staff") == 0, "gr_name");
    CHECK(gr->gr_gid == 100,                 "gr_gid");

    struct group *gr2 = getgrgid(999);
    CHECK(gr2 == NULL, "存在しない gid は NULL");
}

static void test_getgrnam_r(void)
{
    puts("getgrnam_r");

    struct group gr;
    char buf[1024];
    struct group *result;

    int ret = getgrnam_r("staff", &gr, buf, sizeof(buf), &result);
    CHECK(ret == 0,                          "返値 0");
    CHECK(result == &gr,                     "result が gr を指す");
    CHECK(strcmp(gr.gr_name, "staff") == 0,  "gr_name");
    CHECK(gr.gr_gid == 100,                  "gr_gid");

    ret = getgrnam_r("ghost", &gr, buf, sizeof(buf), &result);
    CHECK(ret == ENOENT, "存在しないグループは ENOENT");
    CHECK(result == NULL, "result が NULL");
}

static void test_getgrgid_r(void)
{
    puts("getgrgid_r");

    struct group gr;
    char buf[1024];
    struct group *result;

    int ret = getgrgid_r(100, &gr, buf, sizeof(buf), &result);
    CHECK(ret == 0,       "返値 0");
    CHECK(result != NULL, "result が非 NULL");
    CHECK(gr.gr_gid == 100, "gr_gid");

    ret = getgrgid_r(999, &gr, buf, sizeof(buf), &result);
    CHECK(ret == ENOENT, "存在しない gid は ENOENT");
    CHECK(result == NULL, "result が NULL");
}

static void test_empty_group_members(void)
{
    puts("空メンバーグループ");

    struct group *gr = getgrnam("empty");
    CHECK(gr != NULL,   "empty グループが見つかる");
    CHECK(gr->gr_gid == 200, "gr_gid");
    CHECK(gr->gr_mem[0] == NULL, "メンバーなし → 先頭が NULL");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    test_getpwnam();
    test_getpwuid();
    test_getpwnam_r();
    test_getpwuid_r();
    test_getgrnam();
    test_getgrgid();
    test_getgrnam_r();
    test_getgrgid_r();
    test_empty_group_members();
    test_fallback();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
