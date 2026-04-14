/**
 * main.ts — NSS Forward HTTP server (Deno)
 *
 * Translates HTTP requests for passwd/group entries into LDAP queries
 * and returns /etc/passwd or /etc/group formatted plain text.
 *
 * Environment variables:
 *   LDAP_URL        ldap://hostname:port   (default: ldap://localhost:389)
 *   LDAP_BIND_DN    cn=admin,dc=example,dc=com
 *   LDAP_BIND_PW    secret
 *   LDAP_USER_BASE  ou=users,dc=example,dc=com
 *   LDAP_GROUP_BASE ou=groups,dc=example,dc=com
 *   PORT            8080
 */

import {
  ldapBind,
  ldapClose,
  ldapConnect,
  type LdapEntry,
  ldapSearch,
} from "./ldap.ts";

// --------------------------------------------------------------------------
// Config
// --------------------------------------------------------------------------

function env(key: string, fallback = ""): string {
  return Deno.env.get(key) ?? fallback;
}

function parseLdapUrl(url: string): { hostname: string; port: number } {
  const s = url.replace(/^ldap:\/\//, "");
  const [hostname, portStr] = s.split(":");
  return { hostname, port: parseInt(portStr ?? "389") };
}

// --------------------------------------------------------------------------
// LDAP attributes
// --------------------------------------------------------------------------

const USER_ATTRS = [
  "uid",
  "uidNumber",
  "gidNumber",
  "cn",
  "gecos",
  "homeDirectory",
  "loginShell",
  "sambaSID",
];
const GROUP_ATTRS = ["cn", "gidNumber", "memberUid"];

// --------------------------------------------------------------------------
// Conversion helpers (exported for testing)
// --------------------------------------------------------------------------

function attr(entry: LdapEntry, name: string): string {
  return entry.attrs[name]?.[0] ?? "";
}

function attrAll(entry: LdapEntry, name: string): string[] {
  return entry.attrs[name] ?? [];
}

/**
 * Derive uidNumber from sambaSID RID when uidNumber is absent.
 * SID format: S-1-5-21-...-RID  →  uid = 10000 + RID
 */
export function uidFromSambaSID(sid: string): string | null {
  // Valid SID: S-1-5-21-<sub1>-<sub2>-<sub3>-<RID>  (最低 5 セグメント)
  const parts = sid.split("-");
  if (parts.length < 5) return null;
  const rid = parseInt(parts[parts.length - 1]);
  if (isNaN(rid)) return null;
  return String(10000 + rid);
}

export function entryToPasswd(entry: LdapEntry): string | null {
  const name = attr(entry, "uid");
  if (!name) return null;

  let uid = attr(entry, "uidnumber");
  if (!uid) {
    const sid = attr(entry, "sambasid");
    uid = uidFromSambaSID(sid) ?? "";
  }
  if (!uid) return null;

  const gid = attr(entry, "gidnumber") || "0";
  const gecos = attr(entry, "gecos") || attr(entry, "cn") || name;
  const home = attr(entry, "homedirectory") || `/home/${name}`;
  const shell = attr(entry, "loginshell") || "/bin/sh";

  return `${name}:x:${uid}:${gid}:${gecos}:${home}:${shell}`;
}

export function entryToGroup(entry: LdapEntry): string | null {
  const name = attr(entry, "cn");
  const gid = attr(entry, "gidnumber");
  if (!name || !gid) return null;
  const members = attrAll(entry, "memberuid").join(",");
  return `${name}:x:${gid}:${members}`;
}

// --------------------------------------------------------------------------
// HTTP handler (injectable for testing via createHandler)
// --------------------------------------------------------------------------

export interface Lookups {
  lookupPasswdByName(name: string): Promise<string | null>;
  lookupPasswdByUid(uid: string): Promise<string | null>;
  lookupGroupByName(name: string): Promise<string | null>;
  lookupGroupByGid(gid: string): Promise<string | null>;
}

export function createHandler(
  lookups: Lookups,
): (req: Request) => Promise<Response> {
  const routes: [RegExp, (m: RegExpMatchArray) => Promise<string | null>][] = [
    [/^\/passwd\/uid\/(\d+)$/, ([, uid]) => lookups.lookupPasswdByUid(uid)],
    [/^\/passwd\/([^/]+)$/, ([, name]) => lookups.lookupPasswdByName(name)],
    [/^\/group\/gid\/(\d+)$/, ([, gid]) => lookups.lookupGroupByGid(gid)],
    [/^\/group\/([^/]+)$/, ([, name]) => lookups.lookupGroupByName(name)],
  ];

  return async (req: Request): Promise<Response> => {
    const path = new URL(req.url).pathname;

    for (const [re, fn] of routes) {
      const m = path.match(re);
      if (m) {
        try {
          const result = await fn(m);
          if (result === null) {
            return new Response("Not Found\n", { status: 404 });
          }
          return new Response(result + "\n", {
            status: 200,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          });
        } catch (err) {
          console.error("Handler error:", err);
          return new Response("Internal Server Error\n", { status: 500 });
        }
      }
    }

    return new Response("Not Found\n", { status: 404 });
  };
}

// --------------------------------------------------------------------------
// Production wiring (only when run directly)
// --------------------------------------------------------------------------

if (import.meta.main) {
  const ldapUrl = env("LDAP_URL", "ldap://localhost:389");
  const bindDN = env("LDAP_BIND_DN");
  const bindPW = env("LDAP_BIND_PW");
  const userBase = env("LDAP_USER_BASE");
  const groupBase = env("LDAP_GROUP_BASE");
  const port = parseInt(env("PORT", "8080"));

  const { hostname: ldapHost, port: ldapPort } = parseLdapUrl(ldapUrl);

  let ldapConn: Awaited<ReturnType<typeof ldapConnect>> | null = null;

  const getConn = async () => {
    if (ldapConn) return ldapConn;
    ldapConn = await ldapConnect(ldapHost, ldapPort);
    await ldapBind(ldapConn, bindDN, bindPW);
    return ldapConn;
  };

  const withConn = async <T>(
    fn: (c: Awaited<ReturnType<typeof ldapConnect>>) => Promise<T>,
  ): Promise<T> => {
    try {
      return await fn(await getConn());
    } catch {
      if (ldapConn) {
        ldapClose(ldapConn);
        ldapConn = null;
      }
      return await fn(await getConn());
    }
  };

  const lookups: Lookups = {
    lookupPasswdByName: async (name) => {
      const entries = await withConn((c) =>
        ldapSearch(c, userBase, "uid", name, USER_ATTRS)
      );
      for (const e of entries) {
        const l = entryToPasswd(e);
        if (l) return l;
      }
      return null;
    },
    lookupPasswdByUid: async (uid) => {
      const entries = await withConn((c) =>
        ldapSearch(c, userBase, "uidNumber", uid, USER_ATTRS)
      );
      for (const e of entries) {
        const l = entryToPasswd(e);
        if (l) return l;
      }
      return null;
    },
    lookupGroupByName: async (name) => {
      const entries = await withConn((c) =>
        ldapSearch(c, groupBase, "cn", name, GROUP_ATTRS)
      );
      for (const e of entries) {
        const l = entryToGroup(e);
        if (l) return l;
      }
      return null;
    },
    lookupGroupByGid: async (gid) => {
      const entries = await withConn((c) =>
        ldapSearch(c, groupBase, "gidNumber", gid, GROUP_ATTRS)
      );
      for (const e of entries) {
        const l = entryToGroup(e);
        if (l) return l;
      }
      return null;
    },
  };

  console.log(`NSS Forward server starting on port ${port}`);
  console.log(
    `LDAP: ${ldapUrl}, userBase: ${userBase}, groupBase: ${groupBase}`,
  );

  try {
    await getConn();
    console.log("LDAP bind successful");
  } catch (e) {
    console.error("Initial LDAP bind failed (will retry on first request):", e);
    ldapConn = null;
  }

  Deno.serve({ port }, createHandler(lookups));
}
