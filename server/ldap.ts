/**
 * ldap.ts — Minimal LDAPv3 client (Bind + Search, equality filter only)
 *
 * Uses Deno.connect (TCP). No external dependencies.
 */

import {
  type BerNode,
  concat,
  decodeOne,
  encodeBoolean,
  encodeEnumerated,
  encodeInt,
  encodeOctetString,
  encodePrimitive,
  encodeSequence,
  rawToInt,
  rawToString,
} from "./ber.ts";

// --------------------------------------------------------------------------
// LDAP Application tags (constructed unless noted)
// --------------------------------------------------------------------------
const TAG_BIND_REQUEST = 0x60; // [APPLICATION 0] constructed
const TAG_BIND_RESPONSE = 0x61;
const TAG_SEARCH_REQUEST = 0x63; // [APPLICATION 3] constructed
const TAG_SEARCH_RESULT_ENTRY = 0x64;
const TAG_SEARCH_RESULT_DONE = 0x65;

// Filter tags (context-specific)
const TAG_FILTER_EQUALITY = 0xa3; // [3] constructed  (equalityMatch)

// Attribute value assertion (for equality filter)
const TAG_ATTRIBUTE_VALUE_LIST = 0x30; // SEQUENCE OF

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

export interface LdapEntry {
  dn: string;
  attrs: Record<string, string[]>;
}

export interface LdapConnection {
  conn: Deno.TcpConn;
  msgId: number;
  /** 受信済みだがまだ消費していないバイト列 */
  _readBuf: Uint8Array;
}

// --------------------------------------------------------------------------
// Low-level send/recv
// --------------------------------------------------------------------------

async function sendMessage(
  lc: LdapConnection,
  appPdu: Uint8Array,
): Promise<void> {
  lc.msgId++;
  const envelope = encodeSequence([
    encodeInt(lc.msgId),
    appPdu,
  ]);
  let off = 0;
  while (off < envelope.length) {
    const n = await lc.conn.write(envelope.slice(off));
    off += n;
  }
}

async function recvMessage(lc: LdapConnection): Promise<BerNode> {
  // 複数メッセージが同一 TCP パケットで届くことがある。
  // _readBuf に残存バイトを保持し、次回呼び出しで先に消費する。
  const tmp = new Uint8Array(8192);
  while (true) {
    if (lc._readBuf.length > 0) {
      try {
        const { node, next } = decodeOne(lc._readBuf);
        lc._readBuf = lc._readBuf.slice(next);
        return node;
      } catch {
        // バッファが足りない → さらに読む
      }
    }
    const n = await lc.conn.read(tmp);
    if (n === null) throw new Error("LDAP connection closed");
    lc._readBuf = concat([lc._readBuf, tmp.slice(0, n)]);
  }
}

// --------------------------------------------------------------------------
// Connect
// --------------------------------------------------------------------------

export async function ldapConnect(
  hostname: string,
  port: number,
): Promise<LdapConnection> {
  const conn = await Deno.connect({ hostname, port, transport: "tcp" });
  return { conn, msgId: 0, _readBuf: new Uint8Array(0) };
}

export function ldapClose(lc: LdapConnection): void {
  try {
    lc.conn.close();
  } catch { /* ignore */ }
}

// --------------------------------------------------------------------------
// Bind (Simple)
// --------------------------------------------------------------------------

export async function ldapBind(
  lc: LdapConnection,
  bindDN: string,
  password: string,
): Promise<void> {
  // BindRequest ::= [APPLICATION 0] SEQUENCE {
  //   version   INTEGER (1..127),
  //   name      LDAPDN,
  //   authentication AuthenticationChoice }
  // Simple password: [0] IMPLICIT OCTET STRING
  const simpleAuth = encodePrimitive(0x80, new TextEncoder().encode(password));

  const bindReq = encodeSequence([
    encodeInt(3), // version = 3
    encodeOctetString(bindDN),
    simpleAuth,
  ], TAG_BIND_REQUEST);

  await sendMessage(lc, bindReq);
  const resp = await recvMessage(lc);

  // envelope is SEQUENCE { msgId, BindResponse }
  if (!resp.children || resp.children.length < 2) {
    throw new Error("Malformed Bind response");
  }

  const bindResp = resp.children[1];
  if (bindResp.tag !== TAG_BIND_RESPONSE || !bindResp.children) {
    throw new Error("Expected BindResponse");
  }

  const resultCode = rawToInt(bindResp.children[0].raw);
  if (resultCode !== 0) {
    const msg = bindResp.children[2]
      ? rawToString(bindResp.children[2].raw)
      : "";
    throw new Error(`Bind failed (code ${resultCode}): ${msg}`);
  }
}

// --------------------------------------------------------------------------
// Search (equality filter only, all scope=subtree)
// --------------------------------------------------------------------------

function buildEqualityFilter(attr: string, value: string): Uint8Array {
  // equalityMatch [3] SEQUENCE { attributeDesc, assertionValue }
  return encodeSequence([
    encodeOctetString(attr),
    encodeOctetString(value),
  ], TAG_FILTER_EQUALITY);
}

function buildSearchRequest(
  baseDN: string,
  filter: Uint8Array,
  attributes: string[],
): Uint8Array {
  // SearchRequest ::= [APPLICATION 3] SEQUENCE {
  //   baseObject   LDAPDN,
  //   scope        ENUMERATED {baseObject(0), singleLevel(1), wholeSubtree(2)},
  //   derefAliases ENUMERATED {neverDerefAliases(0),...},
  //   sizeLimit    INTEGER,
  //   timeLimit    INTEGER,
  //   typesOnly    BOOLEAN,
  //   filter       Filter,
  //   attributes   AttributeDescriptionList }

  const attrList = encodeSequence(
    attributes.map((a) => encodeOctetString(a)),
    TAG_ATTRIBUTE_VALUE_LIST,
  );

  return encodeSequence([
    encodeOctetString(baseDN),
    encodeEnumerated(2), // wholeSubtree
    encodeEnumerated(0), // neverDerefAliases
    encodeInt(0), // sizeLimit = unlimited
    encodeInt(30), // timeLimit = 30s
    encodeBoolean(false), // typesOnly = false
    filter,
    attrList,
  ], TAG_SEARCH_REQUEST);
}

function parseEntry(node: BerNode): LdapEntry {
  // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
  //   objectName LDAPDN,
  //   attributes PartialAttributeList }
  if (!node.children || node.children.length < 2) {
    throw new Error("Malformed SearchResultEntry");
  }

  const dn = rawToString(node.children[0].raw);
  const attrs: Record<string, string[]> = {};

  const attrList = node.children[1];
  for (const attrSeq of attrList.children ?? []) {
    // PartialAttribute ::= SEQUENCE { type, vals SET OF }
    if (!attrSeq.children || attrSeq.children.length < 2) continue;
    const type = rawToString(attrSeq.children[0].raw).toLowerCase();
    const vals = (attrSeq.children[1].children ?? []).map((v) =>
      rawToString(v.raw)
    );
    attrs[type] = vals;
  }

  return { dn, attrs };
}

export async function ldapSearch(
  lc: LdapConnection,
  baseDN: string,
  filterAttr: string,
  filterValue: string,
  attributes: string[],
): Promise<LdapEntry[]> {
  const filter = buildEqualityFilter(filterAttr, filterValue);
  const req = buildSearchRequest(baseDN, filter, attributes);
  await sendMessage(lc, req);

  const entries: LdapEntry[] = [];

  while (true) {
    const msg = await recvMessage(lc);
    if (!msg.children || msg.children.length < 2) {
      throw new Error("Malformed LDAP message");
    }

    const pdu = msg.children[1];

    if (pdu.tag === TAG_SEARCH_RESULT_ENTRY) {
      entries.push(parseEntry(pdu));
    } else if (pdu.tag === TAG_SEARCH_RESULT_DONE) {
      const resultCode = pdu.children ? rawToInt(pdu.children[0].raw) : -1;
      if (resultCode !== 0 && resultCode !== 32 /* noSuchObject */) {
        const errMsg = pdu.children?.[2]
          ? rawToString(pdu.children[2].raw)
          : "";
        throw new Error(`Search failed (code ${resultCode}): ${errMsg}`);
      }
      break;
    }
    // Ignore other PDUs (referrals, etc.)
  }

  return entries;
}
