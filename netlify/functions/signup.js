// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";
import * as dns from "node:dns";
try { dns.setDefaultResultOrder?.("ipv4first"); } catch {}

import pg from "pg";
const { Pool } = pg;

/* ===================== CONFIG ===================== */
const TABLE = "signups";
const SITE_SLUG = "veteranverify"; // your Netlify site before .netlify.app
const PROD_DOMAINS = ["veteranverify.net", "www.veteranverify.net"];
const DEBUG = true; // flip to false when stable
const HARDCODED_SUPABASE_URL = "https://hyuawfauycyeqbhfwxx.supabase.co";

/* ================= ENV ============================ */
const SUPABASE_URL = (
  (process.env.SUPABASE_URL || HARDCODED_SUPABASE_URL || "").trim()
).replace(/\/+$/, "");

const SERVICE_KEY = (
  process.env.SUPABASE_SERVICE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SECRET ||
  ""
).trim();

const DB_URL = (process.env.SUPABASE_DB_URL || process.env.DATABASE_URL || "").trim();

const WEBHOOK_TOKEN = (
  process.env.FORM_WEBHOOK_SECRET || process.env.WEBHOOK_TOKEN || ""
).trim();

/* ============== CLIENTS (global reuse) ============ */
const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false },
});

let pool = null;
if (DB_URL) {
  pool = new Pool({
    connectionString: DB_URL,
    ssl: { rejectUnauthorized: false },   // works with ?sslmode=require
    max: 3,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
  });
}

/* ===================== HELPERS ==================== */
const log = (...a) => DEBUG && console.log("[signup]", ...a);
const errlog = (...a) => console.error("[signup]", ...a);

const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
const asBool  = (v) => v === true || v === "true" || v === "1" || v === "yes" || v === "on";

const tryJson = (s) => { try { return JSON.parse(s); } catch { return null; } };

const getBodyString = (event) =>
  !event?.body ? "" : (event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body);

const pickNetlifyData = (obj) => obj?.payload?.data ?? obj?.data ?? obj;

const isAllowedHostname = (h) => {
  if (!h) return false;
  if (h === `${SITE_SLUG}.netlify.app`) return true;
  if (h.endsWith(`--${SITE_SLUG}.netlify.app`)) return true; // branch/preview
  if (PROD_DOMAINS.includes(h)) return true;
  if (h === "localhost" || h === "127.0.0.1") return true;
  return false;
};

const getRequestOrigin = (headers) => {
  const h = headers || {};
  const o = h.origin || h.Origin;
  if (o) return o;
  const r = h.referer || h.Referer;
  if (!r) return null;
  try { return new URL(r).origin; } catch { return null; }
};

/* ============== REST vs SQL helpers =============== */
async function restPing() {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/`, {
      method: "HEAD",
      headers: { apikey: SERVICE_KEY, authorization: `Bearer ${SERVICE_KEY}` },
    });
    return r.ok || r.status === 404; // any response means reachable
  } catch (e) {
    errlog("REST ping failed:", e?.message || e);
    return false;
  }
}

async function insertViaREST(row) {
  const { data, error } = await supabase.from(TABLE).insert(row).select("id");
  if (error) throw new Error(error.message || "REST insert failed");
  return data?.[0]?.id ?? null;
}

async function insertViaSQL(row) {
  if (!pool) throw new Error("SQL pool not configured (SUPABASE_DB_URL missing)");
  const client = await pool.connect();
  try {
    const q = `
      insert into public.${TABLE}
        (first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua)
      values
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      returning id
    `;
    const vals = [
      row.first_name, row.last_name, row.email, row.role, row.state,
      row.organization, row.message, row.updates_opt_in, row.ip, row.ua
    ];
    const { rows } = await client.query(q, vals);
    return rows?.[0]?.id ?? null;
  } finally {
    client.release();
  }
}

/* ===================== HANDLER ==================== */
export async function handler(event) {
  console.log("[signup] invoked", {
    t: new Date().toISOString(),
    method: event.httpMethod,
    path: event.path,
    host: event.headers?.host || null,
  });

  const hdrs = event.headers || {};
  const requestOrigin = getRequestOrigin(hdrs);
  let requestHostname = null;
  try { requestHostname = requestOrigin ? new URL(requestOrigin).hostname : null; } catch {}
  const allowedOrigin = !!requestHostname && isAllowedHostname(requestHostname);

  // Build URL for webhook token
  const rawUrl =
    event.rawUrl ||
    `https://${hdrs.host}${event.path}${event.rawQuery ? `?${event.rawQuery}` : ""}`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook = Boolean(token && WEBHOOK_TOKEN && token === WEBHOOK_TOKEN);

  // CORS
  const strictCors = allowedOrigin
    ? {
        "Access-Control-Allow-Origin": requestOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        Vary: "Origin",
      }
    : {};

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    const acrh =
      hdrs["access-control-request-headers"] ||
      hdrs["Access-Control-Request-Headers"] ||
      "Content-Type";
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": requestOrigin || "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": acrh,
        Vary: "Origin, Access-Control-Request-Headers",
      },
      body: "",
    };
  }

  // Gate POSTs
  if (!allowedOrigin && !isWebhook) {
    log("403 Forbidden", { requestOrigin, requestHostname, isWebhook });
    return { statusCode: 403, headers: strictCors, body: "Forbidden" };
  }

  // Validate config (REST path)
  if (!/^https:\/\/[^/]+\.supabase\.co$/.test(SUPABASE_URL)) {
    errlog("Bad SUPABASE_URL value:", SUPABASE_URL);
    // keep going; SQL might still be configured
  }
  if (!SERVICE_KEY) {
    errlog("Missing SUPABASE_SERVICE_KEY");
    // keep going; SQL might still be configured
  }

  // ---- Parse body ----
  try {
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    const bodyStr = getBodyString(event);
    log("content-type:", ct || "(none)", "| bytes:", bodyStr.length);

    let payload = {};
    if (ct.includes("application/json")) {
      payload = pickNetlifyData(tryJson(bodyStr) || {});
      log("parsed json keys:", Object.keys(payload || {}));
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(bodyStr || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]");
      log("parsed form-encoded keys:", Object.keys(payload || {}));
    } else {
      const maybe = tryJson(bodyStr);
      if (maybe) {
        payload = pickNetlifyData(maybe);
        log("parsed json (no ct) keys:", Object.keys(payload || {}));
      } else {
        return { statusCode: 415, headers: strictCors, body: "Unsupported content type" };
      }
    }

    // Honeypot
    if (payload["bot-field"]) {
      log("honeypot hit; ignoring");
      return { statusCode: 204, headers: strictCors, body: "" };
    }

    // Normalize row
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  = fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    const email = String(payload.email || "").trim();
    if (!isEmail(email) || email.toLowerCase() === "you@example.com") {
      return { statusCode: 400, headers: strictCors, body: "Invalid email" };
    }

    let role = null;
    if (Array.isArray(payload["role[]"]) && payload["role[]"].length) {
      role = payload["role[]"].join(", ");
    } else if (payload.role) {
      role = String(payload.role);
    }

    const state           = payload.state || null;
    const organization    = payload.organization || null;
    const message         = payload.message || null;
    const updates_opt_in  = asBool(payload.updates) || asBool(payload.updates_opt_in);

    const ip =
      hdrs["x-nf-client-connection-ip"] ||
      hdrs["client-ip"] ||
      (hdrs["x-forwarded-for"] || "").split(",")[0].trim() ||
      hdrs["x-real-ip"] || null;

    const ua = String(hdrs["user-agent"] || "");

    const row = {
      first_name, last_name, email, role, state,
      organization, message, updates_opt_in, ip, ua,
    };

    // Decide driver: try REST if reachable; otherwise SQL
    let id = null;
    const restOK = await restPing();
    log("REST reachable?", restOK, "| SQL configured?", Boolean(pool));

    if (restOK && SERVICE_KEY) {
      try {
        log("Using REST insert");
        id = await insertViaREST(row);
      } catch (e) {
        errlog("REST insert failed, will try SQL:", e?.message || e);
        if (pool) {
          log("Falling back to SQL insert");
          id = await insertViaSQL(row);
        } else {
          throw e;
        }
      }
    } else if (pool) {
      log("Using SQL insert");
      id = await insertViaSQL(row);
    } else {
      return { statusCode: 500, headers: strictCors, body: "No database path available" };
    }

    log("inserted id:", id);
    return {
      statusCode: 200,
      headers: { ...strictCors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true, id }),
    };
  } catch (e) {
    errlog("Unhandled error:", e?.message || e);
    return { statusCode: 500, headers: strictCors, body: "Server error" };
  }
}
