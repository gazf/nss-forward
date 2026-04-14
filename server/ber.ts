/**
 * ber.ts — Minimal ASN.1 BER encoder/decoder for LDAPv3
 *
 * Tags used by LDAP:
 *   SEQUENCE      0x30
 *   INTEGER       0x02
 *   OCTET STRING  0x04
 *   ENUMERATED    0x0a
 *   BOOLEAN       0x01
 *   Application   0x60+ (context-specific class, constructed/primitive)
 */

export type BerValue =
  | { tag: number; value: Uint8Array } // leaf (primitive or opaque constructed)
  | { tag: number; children: BerValue[] }; // decoded constructed

// --------------------------------------------------------------------------
// Encoding
// --------------------------------------------------------------------------

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  if (len < 0x10000) return new Uint8Array([0x82, len >> 8, len & 0xff]);
  throw new Error("Length too large");
}

export function encodePrimitive(tag: number, data: Uint8Array): Uint8Array {
  const len = encodeLength(data.length);
  const out = new Uint8Array(1 + len.length + data.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(data, 1 + len.length);
  return out;
}

export function encodeSequence(children: Uint8Array[], tag = 0x30): Uint8Array {
  const body = concat(children);
  const len = encodeLength(body.length);
  const out = new Uint8Array(1 + len.length + body.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(body, 1 + len.length);
  return out;
}

export function encodeInt(n: number): Uint8Array {
  // Minimal big-endian signed
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v >>= 8;
  } while (v !== 0 && v !== -1);
  // Sign-extend if needed
  if (n >= 0 && (bytes[0] & 0x80)) bytes.unshift(0);
  if (n < 0 && !(bytes[0] & 0x80)) bytes.unshift(0xff);
  return encodePrimitive(0x02, new Uint8Array(bytes));
}

export function encodeOctetString(s: string): Uint8Array {
  return encodePrimitive(0x04, new TextEncoder().encode(s));
}

export function encodeEnumerated(n: number): Uint8Array {
  const data = encodeInt(n);
  // Replace tag 0x02 with 0x0a
  const out = new Uint8Array(data.length);
  out.set(data);
  out[0] = 0x0a;
  return out;
}

export function encodeBoolean(v: boolean): Uint8Array {
  return encodePrimitive(0x01, new Uint8Array([v ? 0xff : 0x00]));
}

export function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// --------------------------------------------------------------------------
// Decoding
// --------------------------------------------------------------------------

export interface BerNode {
  tag: number;
  constructed: boolean;
  raw: Uint8Array; // content octets only
  children?: BerNode[]; // present if constructed
}

function decodeLength(
  buf: Uint8Array,
  off: number,
): { len: number; next: number } {
  const first = buf[off++];
  if (first < 0x80) return { len: first, next: off };
  const numBytes = first & 0x7f;
  let len = 0;
  for (let i = 0; i < numBytes; i++) {
    len = (len << 8) | buf[off++];
  }
  return { len, next: off };
}

export function decodeOne(
  buf: Uint8Array,
  off = 0,
): { node: BerNode; next: number } {
  const tag = buf[off++];
  const constructed = !!(tag & 0x20);
  const { len, next: contentStart } = decodeLength(buf, off);
  const raw = buf.slice(contentStart, contentStart + len);
  const node: BerNode = { tag, constructed, raw };
  if (constructed) {
    node.children = decodeAll(raw);
  }
  return { node, next: contentStart + len };
}

export function decodeAll(buf: Uint8Array): BerNode[] {
  const nodes: BerNode[] = [];
  let off = 0;
  while (off < buf.length) {
    const { node, next } = decodeOne(buf, off);
    nodes.push(node);
    off = next;
  }
  return nodes;
}

export function rawToString(raw: Uint8Array): string {
  return new TextDecoder().decode(raw);
}

export function rawToInt(raw: Uint8Array): number {
  let v = raw[0] & 0x80 ? -1 : 0;
  for (const b of raw) v = (v << 8) | b;
  return v;
}
