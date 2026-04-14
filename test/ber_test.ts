/**
 * ber_test.ts
 *
 * BER エンコード/デコードの正しさを検証する。
 * 各プリミティブ型の仕様準拠と、encode→decode のラウンドトリップを確認する。
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  concat,
  decodeAll,
  decodeOne,
  encodeBoolean,
  encodeEnumerated,
  encodeInt,
  encodeOctetString,
  encodePrimitive,
  encodeSequence,
  rawToInt,
  rawToString,
} from "../server/ber.ts";

// --------------------------------------------------------------------------
// encodeInt
// --------------------------------------------------------------------------

Deno.test("encodeInt: 0 は最小長の 1 バイト値になる", () => {
  assertEquals(encodeInt(0), new Uint8Array([0x02, 0x01, 0x00]));
});

Deno.test("encodeInt: 正の値で最上位ビットが立つ場合はゼロパディングされる", () => {
  // 128 = 0x80 → 符号拡張が必要 → 0x00 0x80
  assertEquals(encodeInt(128), new Uint8Array([0x02, 0x02, 0x00, 0x80]));
  assertEquals(encodeInt(255), new Uint8Array([0x02, 0x02, 0x00, 0xff]));
});

Deno.test("encodeInt: 127 以下は 1 バイト値", () => {
  assertEquals(encodeInt(1), new Uint8Array([0x02, 0x01, 0x01]));
  assertEquals(encodeInt(127), new Uint8Array([0x02, 0x01, 0x7f]));
});

Deno.test("encodeInt: 負の値 -1 は 0xff の 1 バイト", () => {
  assertEquals(encodeInt(-1), new Uint8Array([0x02, 0x01, 0xff]));
});

Deno.test("encodeInt: -128 は 0x80 の 1 バイト (追加ゼロ不要)", () => {
  assertEquals(encodeInt(-128), new Uint8Array([0x02, 0x01, 0x80]));
});

Deno.test("encodeInt: 256 は 2 バイト値", () => {
  assertEquals(encodeInt(256), new Uint8Array([0x02, 0x02, 0x01, 0x00]));
});

// --------------------------------------------------------------------------
// encodeOctetString
// --------------------------------------------------------------------------

Deno.test("encodeOctetString: ASCII 文字列", () => {
  const enc = encodeOctetString("hi");
  assertEquals(enc[0], 0x04); // tag
  assertEquals(enc[1], 2); // length
  assertEquals(enc[2], 0x68); // 'h'
  assertEquals(enc[3], 0x69); // 'i'
});

Deno.test("encodeOctetString: 空文字列は length=0", () => {
  assertEquals(encodeOctetString(""), new Uint8Array([0x04, 0x00]));
});

// --------------------------------------------------------------------------
// encodeEnumerated
// --------------------------------------------------------------------------

Deno.test("encodeEnumerated: tag が 0x0a になる", () => {
  const enc = encodeEnumerated(0);
  assertEquals(enc[0], 0x0a);
  assertEquals(enc[enc.length - 1], 0x00);
});

Deno.test("encodeEnumerated: 値 49 (invalidCredentials)", () => {
  const enc = encodeEnumerated(49);
  assertEquals(enc[0], 0x0a);
  assertEquals(enc[enc.length - 1], 49);
});

// --------------------------------------------------------------------------
// encodeBoolean
// --------------------------------------------------------------------------

Deno.test("encodeBoolean: true は 0xff", () => {
  assertEquals(encodeBoolean(true), new Uint8Array([0x01, 0x01, 0xff]));
});

Deno.test("encodeBoolean: false は 0x00", () => {
  assertEquals(encodeBoolean(false), new Uint8Array([0x01, 0x01, 0x00]));
});

// --------------------------------------------------------------------------
// encodePrimitive
// --------------------------------------------------------------------------

Deno.test("encodePrimitive: 任意 tag でエンコードできる", () => {
  const data = new Uint8Array([0xde, 0xad]);
  const enc = encodePrimitive(0x80, data);
  assertEquals(enc[0], 0x80);
  assertEquals(enc[1], 2);
  assertEquals(enc[2], 0xde);
  assertEquals(enc[3], 0xad);
});

// --------------------------------------------------------------------------
// encodeSequence
// --------------------------------------------------------------------------

Deno.test("encodeSequence: デフォルト tag 0x30 で子をラップする", () => {
  const child = encodeInt(1);
  const seq = encodeSequence([child]);
  assertEquals(seq[0], 0x30); // SEQUENCE tag
  assertEquals(seq[1], child.length); // length
  assertEquals(seq.slice(2), child);
});

Deno.test("encodeSequence: カスタム tag (Application tag) を使える", () => {
  const seq = encodeSequence([encodeInt(0)], 0x60);
  assertEquals(seq[0], 0x60);
});

Deno.test("encodeSequence: 複数の子が正しく連結される", () => {
  const a = encodeInt(1);
  const b = encodeOctetString("x");
  const seq = encodeSequence([a, b]);
  const body = seq.slice(2);
  assertEquals(body.length, a.length + b.length);
});

// --------------------------------------------------------------------------
// 可変長エンコーディング (length >= 128)
// --------------------------------------------------------------------------

Deno.test("encodeSequence: 長さ 128 以上で多バイト length フィールドが使われる", () => {
  // 130 バイトのダミーデータ
  const big = encodePrimitive(0x04, new Uint8Array(130));
  const seq = encodeSequence([big]);
  // length フィールドが 0x81, 0x84 (=132) のはず
  assertEquals(seq[0], 0x30);
  assertEquals(seq[1], 0x81); // 1 バイト長サイズを示す
  assertEquals(seq[2], big.length); // 実際の長さ
});

// --------------------------------------------------------------------------
// decodeOne / decodeAll
// --------------------------------------------------------------------------

Deno.test("decodeOne: primitive を正しくデコードする", () => {
  const orig = encodeOctetString("hello");
  const { node, next } = decodeOne(orig);
  assertEquals(node.tag, 0x04);
  assertEquals(node.constructed, false);
  assertEquals(rawToString(node.raw), "hello");
  assertEquals(next, orig.length);
});

Deno.test("decodeOne: constructed SEQUENCE を子ノードつきでデコードする", () => {
  const seq = encodeSequence([encodeInt(42), encodeOctetString("abc")]);
  const { node } = decodeOne(seq);
  assertEquals(node.tag, 0x30);
  assertEquals(node.constructed, true);
  assertEquals(node.children!.length, 2);
  assertEquals(node.children![0].tag, 0x02);
  assertEquals(rawToInt(node.children![0].raw), 42);
  assertEquals(node.children![1].tag, 0x04);
  assertEquals(rawToString(node.children![1].raw), "abc");
});

Deno.test("decodeAll: バッファ内の複数 TLV をすべて読む", () => {
  const buf = concat([encodeInt(1), encodeInt(2), encodeInt(3)]);
  const nodes = decodeAll(buf);
  assertEquals(nodes.length, 3);
  assertEquals(rawToInt(nodes[0].raw), 1);
  assertEquals(rawToInt(nodes[1].raw), 2);
  assertEquals(rawToInt(nodes[2].raw), 3);
});

Deno.test("decodeAll: 空バッファは空配列", () => {
  assertEquals(decodeAll(new Uint8Array(0)), []);
});

// --------------------------------------------------------------------------
// rawToInt / rawToString
// --------------------------------------------------------------------------

Deno.test("rawToInt: 正の値", () => {
  assertEquals(rawToInt(new Uint8Array([0x00])), 0);
  assertEquals(rawToInt(new Uint8Array([0x7f])), 127);
  assertEquals(rawToInt(new Uint8Array([0x01, 0x00])), 256);
});

Deno.test("rawToInt: 負の値 (最上位ビット=1)", () => {
  assertEquals(rawToInt(new Uint8Array([0xff])), -1);
  assertEquals(rawToInt(new Uint8Array([0x80])), -128);
});

Deno.test("rawToString: UTF-8 文字列に変換できる", () => {
  const bytes = new TextEncoder().encode("nss");
  assertEquals(rawToString(bytes), "nss");
});

// --------------------------------------------------------------------------
// ラウンドトリップ
// --------------------------------------------------------------------------

Deno.test("ラウンドトリップ: ネストした SEQUENCE を encode→decode できる", () => {
  const inner = encodeSequence([
    encodeOctetString("uid"),
    encodeOctetString("alice"),
  ]);
  const outer = encodeSequence([encodeInt(1), inner]);

  const { node } = decodeOne(outer);
  assertEquals(node.children!.length, 2);

  const msgId = rawToInt(node.children![0].raw);
  assertEquals(msgId, 1);

  const innerNode = node.children![1];
  assertEquals(innerNode.constructed, true);
  assertEquals(rawToString(innerNode.children![0].raw), "uid");
  assertEquals(rawToString(innerNode.children![1].raw), "alice");
});
