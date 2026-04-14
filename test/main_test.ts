/**
 * main_test.ts
 *
 * entryToPasswd / entryToGroup の変換ロジックと、
 * createHandler の HTTP ルーティング・レスポンス形式を検証する。
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  createHandler,
  entryToGroup,
  entryToPasswd,
  uidFromSambaSID,
} from "../server/main.ts";
import type { LdapEntry } from "../server/ldap.ts";

// --------------------------------------------------------------------------
// uidFromSambaSID
// --------------------------------------------------------------------------

Deno.test("uidFromSambaSID: RID を 10000 + RID に変換する", () => {
  assertEquals(uidFromSambaSID("S-1-5-21-1234-5678-9012-1001"), "11001");
  assertEquals(uidFromSambaSID("S-1-5-21-0-0-0-500"), "10500");
});

Deno.test("uidFromSambaSID: SID が短すぎるとき null (最低 5 セグメント必要)", () => {
  assertEquals(uidFromSambaSID("S-1-5-21"), null); // 4 セグメント
  assertEquals(uidFromSambaSID("S-1"), null); // 2 セグメント
  assertEquals(uidFromSambaSID(""), null); // 空
});

Deno.test("uidFromSambaSID: 末尾が数値でないとき null", () => {
  assertEquals(uidFromSambaSID("S-1-5-21-abc"), null);
});

// --------------------------------------------------------------------------
// entryToPasswd
// --------------------------------------------------------------------------

function makeUserEntry(
  overrides: Partial<Record<string, string[]>> = {},
): LdapEntry {
  return {
    dn: "uid=alice,ou=users,dc=example,dc=com",
    attrs: {
      uid: ["alice"],
      uidnumber: ["1001"],
      gidnumber: ["100"],
      cn: ["Alice Smith"],
      homedirectory: ["/home/alice"],
      loginshell: ["/bin/bash"],
      ...overrides,
    },
  };
}

Deno.test("entryToPasswd: 全属性が揃っていると正しい passwd 行になる", () => {
  const line = entryToPasswd(makeUserEntry());
  assertEquals(line, "alice:x:1001:100:Alice Smith:/home/alice:/bin/bash");
});

Deno.test("entryToPasswd: password フィールドは常に 'x'", () => {
  const line = entryToPasswd(makeUserEntry())!;
  assertEquals(line.split(":")[1], "x");
});

Deno.test("entryToPasswd: uidNumber がなく sambaSID がある場合 RID から導出する", () => {
  const entry = makeUserEntry({
    uidnumber: [],
    sambasid: ["S-1-5-21-0-0-0-1001"],
  });
  const line = entryToPasswd(entry)!;
  assertEquals(line.split(":")[2], "11001");
});

Deno.test("entryToPasswd: uidNumber も sambaSID もない場合 null", () => {
  const entry = makeUserEntry({ uidnumber: [], sambasid: [] });
  assertEquals(entryToPasswd(entry), null);
});

Deno.test("entryToPasswd: uid がない場合 null", () => {
  const entry = makeUserEntry({ uid: [] });
  assertEquals(entryToPasswd(entry), null);
});

Deno.test("entryToPasswd: gecos がない場合 cn にフォールバックする", () => {
  const entry = makeUserEntry(); // gecos なし、cn = "Alice Smith"
  const line = entryToPasswd(entry)!;
  assertEquals(line.split(":")[4], "Alice Smith");
});

Deno.test("entryToPasswd: gecos があれば cn より優先される", () => {
  const entry = makeUserEntry({ gecos: ["Alice (Engineering)"] });
  const line = entryToPasswd(entry)!;
  assertEquals(line.split(":")[4], "Alice (Engineering)");
});

Deno.test("entryToPasswd: homedirectory がない場合 /home/{name} にフォールバックする", () => {
  const entry = makeUserEntry({ homedirectory: [] });
  const line = entryToPasswd(entry)!;
  assertEquals(line.split(":")[5], "/home/alice");
});

Deno.test("entryToPasswd: loginShell がない場合 /bin/sh にフォールバックする", () => {
  const entry = makeUserEntry({ loginshell: [] });
  const line = entryToPasswd(entry)!;
  assertEquals(line.split(":")[6], "/bin/sh");
});

// --------------------------------------------------------------------------
// entryToGroup
// --------------------------------------------------------------------------

function makeGroupEntry(
  overrides: Partial<Record<string, string[]>> = {},
): LdapEntry {
  return {
    dn: "cn=staff,ou=groups,dc=example,dc=com",
    attrs: {
      cn: ["staff"],
      gidnumber: ["200"],
      memberuid: ["alice", "bob"],
      ...overrides,
    },
  };
}

Deno.test("entryToGroup: 全属性が揃っていると正しい group 行になる", () => {
  assertEquals(entryToGroup(makeGroupEntry()), "staff:x:200:alice,bob");
});

Deno.test("entryToGroup: メンバーなしのとき末尾はコロンで終わる", () => {
  const entry = makeGroupEntry({ memberuid: [] });
  assertEquals(entryToGroup(entry), "staff:x:200:");
});

Deno.test("entryToGroup: cn がない場合 null", () => {
  assertEquals(entryToGroup(makeGroupEntry({ cn: [] })), null);
});

Deno.test("entryToGroup: gidNumber がない場合 null", () => {
  assertEquals(entryToGroup(makeGroupEntry({ gidnumber: [] })), null);
});

// --------------------------------------------------------------------------
// HTTP ハンドラー (createHandler)
// --------------------------------------------------------------------------

/** テスト用の固定応答を返す Lookups スタブ */
function makeStub(overrides: Partial<{
  byName: string | null;
  byUid: string | null;
  byGName: string | null;
  byGid: string | null;
}> = {}) {
  return createHandler({
    lookupPasswdByName: () => Promise.resolve(overrides.byName ?? null),
    lookupPasswdByUid: () => Promise.resolve(overrides.byUid ?? null),
    lookupGroupByName: () => Promise.resolve(overrides.byGName ?? null),
    lookupGroupByGid: () => Promise.resolve(overrides.byGid ?? null),
  });
}

function req(path: string): Request {
  return new Request(`http://localhost${path}`);
}

Deno.test("GET /passwd/{name}: 200 + 改行付き passwd 行", async () => {
  const handler = makeStub({
    byName: "alice:x:1001:100:Alice:/home/alice:/bin/sh",
  });
  const res = await handler(req("/passwd/alice"));
  assertEquals(res.status, 200);
  assertEquals(
    await res.text(),
    "alice:x:1001:100:Alice:/home/alice:/bin/sh\n",
  );
});

Deno.test("GET /passwd/{name}: エントリなしで 404", async () => {
  const handler = makeStub({ byName: null });
  const res = await handler(req("/passwd/nobody"));
  assertEquals(res.status, 404);
});

Deno.test("GET /passwd/uid/{uid}: 200 + passwd 行", async () => {
  const handler = makeStub({
    byUid: "alice:x:1001:100:Alice:/home/alice:/bin/sh",
  });
  const res = await handler(req("/passwd/uid/1001"));
  assertEquals(res.status, 200);
  assertEquals(
    await res.text(),
    "alice:x:1001:100:Alice:/home/alice:/bin/sh\n",
  );
});

Deno.test("GET /passwd/uid/{uid}: 数字でないパスはどのルートにもマッチせず 404", async () => {
  // /passwd/uid/abc は (\d+) にマッチしない。
  // /passwd/([^/]+) も uid/abc にスラッシュが含まれるためマッチしない。
  const handler = makeStub({
    byName: "alice:x:1001:100:Alice:/home/alice:/bin/sh",
  });
  const res = await handler(req("/passwd/uid/abc"));
  assertEquals(res.status, 404);
});

Deno.test("GET /group/{name}: 200 + group 行", async () => {
  const handler = makeStub({ byGName: "staff:x:200:alice,bob" });
  const res = await handler(req("/group/staff"));
  assertEquals(res.status, 200);
  assertEquals(await res.text(), "staff:x:200:alice,bob\n");
});

Deno.test("GET /group/{name}: エントリなしで 404", async () => {
  const handler = makeStub({ byGName: null });
  const res = await handler(req("/group/ghost"));
  assertEquals(res.status, 404);
});

Deno.test("GET /group/gid/{gid}: 200 + group 行", async () => {
  const handler = makeStub({ byGid: "staff:x:200:alice,bob" });
  const res = await handler(req("/group/gid/200"));
  assertEquals(res.status, 200);
  assertEquals(await res.text(), "staff:x:200:alice,bob\n");
});

Deno.test("GET /group/gid/{gid}: エントリなしで 404", async () => {
  const handler = makeStub({ byGid: null });
  const res = await handler(req("/group/gid/999"));
  assertEquals(res.status, 404);
});

Deno.test("未知のパスは 404", async () => {
  const handler = makeStub();
  for (const path of ["/", "/users/alice", "/passwd", "/group"]) {
    const res = await handler(req(path));
    assertEquals(res.status, 404, `expected 404 for ${path}`);
  }
});

Deno.test("ルックアップが例外を投げると 500 を返す", async () => {
  const handler = createHandler({
    lookupPasswdByName: () => Promise.reject(new Error("LDAP down")),
    lookupPasswdByUid: () => Promise.resolve(null),
    lookupGroupByName: () => Promise.resolve(null),
    lookupGroupByGid: () => Promise.resolve(null),
  });
  const res = await handler(req("/passwd/alice"));
  assertEquals(res.status, 500);
});

Deno.test("Content-Type は text/plain; charset=utf-8", async () => {
  const handler = makeStub({
    byName: "alice:x:1001:100:Alice:/home/alice:/bin/sh",
  });
  const res = await handler(req("/passwd/alice"));
  assertEquals(res.headers.get("content-type"), "text/plain; charset=utf-8");
});
