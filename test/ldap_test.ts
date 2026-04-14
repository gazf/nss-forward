/**
 * ldap_test.ts
 *
 * フェイク LDAP サーバーを使って ldap.ts のプロトコル実装を検証する。
 * BER メッセージの送受信・Bind の成功/失敗・Search のエントリ解析が
 * 正しく動作するかを確認する。
 */

import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  ldapBind,
  ldapClose,
  ldapConnect,
  ldapSearch,
} from "../server/ldap.ts";
import {
  concat,
  decodeOne,
  encodeEnumerated,
  encodeInt,
  encodeOctetString,
  encodeSequence,
  rawToInt,
  rawToString,
} from "../server/ber.ts";

// --------------------------------------------------------------------------
// Fake LDAP server helpers
// --------------------------------------------------------------------------

/** LDAPメッセージ全体 (SEQUENCE { msgId, pdu }) を構築する */
function ldapMsg(msgId: number, pdu: Uint8Array): Uint8Array {
  return encodeSequence([encodeInt(msgId), pdu]);
}

/** BindResponse (tag=0x61) */
function bindResponse(msgId: number, resultCode: number): Uint8Array {
  return ldapMsg(
    msgId,
    encodeSequence([
      encodeEnumerated(resultCode),
      encodeOctetString(""),
      encodeOctetString(""),
    ], 0x61),
  );
}

/** SearchResultEntry (tag=0x64) */
function searchResultEntry(
  msgId: number,
  dn: string,
  attrs: Record<string, string[]>,
): Uint8Array {
  const attrList = encodeSequence(
    Object.entries(attrs).map(([name, values]) =>
      encodeSequence([
        encodeOctetString(name),
        encodeSequence(values.map((v) => encodeOctetString(v)), 0x31), // SET OF
      ])
    ),
  );
  return ldapMsg(
    msgId,
    encodeSequence([
      encodeOctetString(dn),
      attrList,
    ], 0x64),
  );
}

/** SearchResultDone (tag=0x65) */
function searchResultDone(msgId: number, resultCode = 0): Uint8Array {
  return ldapMsg(
    msgId,
    encodeSequence([
      encodeEnumerated(resultCode),
      encodeOctetString(""),
      encodeOctetString(""),
    ], 0x65),
  );
}

/** TCP 接続から BER メッセージを 1 つ読み込む */
async function readMsg(
  conn: Deno.TcpConn,
): Promise<{ msgId: number; tag: number; rawPdu: Uint8Array }> {
  const chunks: Uint8Array[] = [];
  const tmp = new Uint8Array(4096);
  while (true) {
    const n = await conn.read(tmp);
    if (n === null) throw new Error("connection closed");
    chunks.push(tmp.slice(0, n));
    try {
      const { node } = decodeOne(concat(chunks));
      const msgId = rawToInt(node.children![0].raw);
      const pdu = node.children![1];
      return { msgId, tag: pdu.tag, rawPdu: pdu.raw };
    } catch {
      // まだデータが足りない
    }
  }
}

interface FakeServer {
  port: number;
  close(): void;
}

type SearchHandler = (
  msgId: number,
  filterAttr: string,
  filterValue: string,
  conn: Deno.TcpConn,
) => Promise<void>;

/**
 * フェイク LDAP サーバーを起動する。
 * - BindRequest に対して resultCode で応答する
 * - SearchRequest に対して searchHandler を呼ぶ
 */
function startFakeLdap(
  bindResultCode: number,
  searchHandler: SearchHandler,
): FakeServer {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;

  const serve = async () => {
    try {
      for await (const conn of listener) {
        handleConn(conn).catch(() => {});
      }
    } catch {
      // listener closed
    }
  };

  const handleConn = async (conn: Deno.TcpConn) => {
    try {
      // Bind
      const bind = await readMsg(conn);
      await conn.write(bindResponse(bind.msgId, bindResultCode));
      if (bindResultCode !== 0) return;

      // Search (複数リクエストを処理)
      while (true) {
        let msg: Awaited<ReturnType<typeof readMsg>>;
        try {
          msg = await readMsg(conn);
        } catch {
          break;
        }
        // SearchRequest tag = 0x63
        if (msg.tag !== 0x63) break;

        // rawPdu を SEQUENCE としてデコードし、7番目の子 (equalityMatch) を取得
        const pduChildren = (() => {
          const { node } = decodeOne(
            new Uint8Array([
              0x30,
              ...encodeLength_(msg.rawPdu.length),
              ...msg.rawPdu,
            ]),
          );
          return node.children ?? [];
        })();

        const filterNode = pduChildren[6]; // equalityMatch
        const filterAttr = rawToString(filterNode.children![0].raw);
        const filterValue = rawToString(filterNode.children![1].raw);

        await searchHandler(msg.msgId, filterAttr, filterValue, conn);
      }
    } finally {
      try {
        conn.close();
      } catch { /* ignore */ }
    }
  };

  serve();
  return {
    port,
    close: () => {
      try {
        listener.close();
      } catch { /* ignore */ }
    },
  };
}

/** BER 可変長エンコード (fake server 内部用) */
function encodeLength_(len: number): number[] {
  if (len < 0x80) return [len];
  if (len < 0x100) return [0x81, len];
  return [0x82, len >> 8, len & 0xff];
}

// --------------------------------------------------------------------------
// Bind のテスト
// --------------------------------------------------------------------------

Deno.test({
  name: "ldapBind: 正常応答 (resultCode=0) でエラーなし",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async () => {});
    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "cn=admin,dc=example,dc=com", "secret");
      // エラーが投げられなければ成功
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

Deno.test({
  name: "ldapBind: resultCode!=0 (invalidCredentials=49) でエラーを投げる",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(49, async () => {});
    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await assertRejects(
        () => ldapBind(lc, "cn=admin,dc=example,dc=com", "wrong"),
        Error,
        "Bind failed",
      );
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

// --------------------------------------------------------------------------
// Search のテスト
// --------------------------------------------------------------------------

Deno.test({
  name: "ldapSearch: エントリが 1 件返るとき属性を正しく解析する",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async (msgId, _attr, _value, conn) => {
      await conn.write(
        searchResultEntry(msgId, "uid=alice,ou=users,dc=example,dc=com", {
          uid: ["alice"],
          uidNumber: ["1001"],
          gidNumber: ["100"],
          cn: ["Alice Smith"],
          homeDirectory: ["/home/alice"],
          loginShell: ["/bin/bash"],
        }),
      );
      await conn.write(searchResultDone(msgId));
    });

    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "", "");
      const entries = await ldapSearch(
        lc,
        "ou=users,dc=example,dc=com",
        "uid",
        "alice",
        ["uid", "uidNumber", "gidNumber", "cn", "homeDirectory", "loginShell"],
      );

      assertEquals(entries.length, 1);
      assertEquals(entries[0].dn, "uid=alice,ou=users,dc=example,dc=com");
      assertEquals(entries[0].attrs["uid"], ["alice"]);
      assertEquals(entries[0].attrs["uidnumber"], ["1001"]);
      assertEquals(entries[0].attrs["gidnumber"], ["100"]);
      assertEquals(entries[0].attrs["cn"], ["Alice Smith"]);
      assertEquals(entries[0].attrs["homedirectory"], ["/home/alice"]);
      assertEquals(entries[0].attrs["loginshell"], ["/bin/bash"]);
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

Deno.test({
  name: "ldapSearch: エントリが 0 件のとき空配列を返す",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async (msgId, _attr, _value, conn) => {
      await conn.write(searchResultDone(msgId)); // エントリなし
    });

    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "", "");
      const entries = await ldapSearch(
        lc,
        "ou=users,dc=example,dc=com",
        "uid",
        "nobody",
        ["uid"],
      );
      assertEquals(entries.length, 0);
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

Deno.test({
  name: "ldapSearch: 複数エントリを返すとき全件を収集する",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async (msgId, _attr, _value, conn) => {
      await conn.write(
        searchResultEntry(msgId, "uid=alice,ou=users,dc=example,dc=com", {
          uid: ["alice"],
          uidNumber: ["1001"],
          gidNumber: ["100"],
          cn: ["Alice"],
        }),
      );
      await conn.write(
        searchResultEntry(msgId, "uid=bob,ou=users,dc=example,dc=com", {
          uid: ["bob"],
          uidNumber: ["1002"],
          gidNumber: ["100"],
          cn: ["Bob"],
        }),
      );
      await conn.write(searchResultDone(msgId));
    });

    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "", "");
      const entries = await ldapSearch(
        lc,
        "ou=users,dc=example,dc=com",
        "gidNumber",
        "100",
        ["uid"],
      );
      assertEquals(entries.length, 2);
      assertEquals(entries[0].attrs["uid"], ["alice"]);
      assertEquals(entries[1].attrs["uid"], ["bob"]);
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

Deno.test({
  name: "ldapSearch: memberUid が複数値のとき全員を配列で返す",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async (msgId, _attr, _value, conn) => {
      await conn.write(
        searchResultEntry(msgId, "cn=staff,ou=groups,dc=example,dc=com", {
          cn: ["staff"],
          gidNumber: ["200"],
          memberUid: ["alice", "bob", "carol"],
        }),
      );
      await conn.write(searchResultDone(msgId));
    });

    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "", "");
      const entries = await ldapSearch(
        lc,
        "ou=groups,dc=example,dc=com",
        "cn",
        "staff",
        ["cn", "gidNumber", "memberUid"],
      );
      assertEquals(entries.length, 1);
      assertEquals(entries[0].attrs["memberuid"], ["alice", "bob", "carol"]);
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});

Deno.test({
  name:
    "ldapSearch: SearchResultDone が noSuchObject (32) のとき空配列を返す (エラーなし)",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const srv = startFakeLdap(0, async (msgId, _attr, _value, conn) => {
      await conn.write(searchResultDone(msgId, 32)); // noSuchObject
    });

    const lc = await ldapConnect("127.0.0.1", srv.port);
    try {
      await ldapBind(lc, "", "");
      const entries = await ldapSearch(
        lc,
        "ou=users,dc=example,dc=com",
        "uid",
        "ghost",
        ["uid"],
      );
      assertEquals(entries.length, 0);
    } finally {
      ldapClose(lc);
      srv.close();
    }
  },
});
