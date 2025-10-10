// netlify/functions/signup.js  (rename to signin.js if you prefer)
// ESM (package.json has "type":"module")

import { createClient } from "@supabase/supabase-js";
import { Pool } from "pg";
import * as dns from "node:dns";

// Prefer IPv4 first (helps undici/fetch + Supabase REST in some regions)
try { dns.setDefaultResultOrder?.("ipv4first"); } catch {}

/* ================== CONFIG ================== */
const TABLE = "signups";
const ALLOWED_ORIGINS = [
  "https://veteranverify.netlify.app",
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "http://localhost:8888",
  "http://127.0.0.1:8888",
];

// Flip to false once you’re happy
const DEBUG = true;

/* ================== ENVs & CLIENTS ================== */
const SUPABASE_URL   = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const SERVICE_KEY    = (process.env.SUPABASE_SERVICE_KEY || "").trim();
const DB_URL         = (process.env.SUPABASE_DB_URL || process.env.DATABASE_URL || "").trim();
const WEBHOOK_TOKEN  = (process.env.FORM_WEBHOOK_SECRET || process.env.WEBHOOK_TOKEN || "").trim();

const supabase = (SUPABASE_URL && SERVICE_KEY)
  ? createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } })
  : null;

const pool = DB_URL
  ? new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } })
  : null;

/* ================== HELPERS ================== */
const log = (...a) => DEBUG && console.log("[signup]", ...a);

const okCors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  Vary: "Origin",
});

const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
const asBool = (v) => v === true || v === "true" || v === "1" || v === "yes" || v === "on";

const tryJson = (s) => { try { return JSON.parse(s); } catch { return null; } };

const getBodyString = (event) => {
  if (!event?.body) return "";
  return event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;
};

// Netlify form webhook payload can be:
// { payload: { data: {...} } }  OR  { data: {...} }  OR  {...fields...}
const pickNetlifyData = (obj) => obj?.payload?.data ?? obj?.data ?? obj;

/* ================== HANDLER ================== */
export async function handler(event) {
  const hdrs = event.headers || {};
  const origin = hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";
  const hasOrigin = Boolean(origin);

  // Build URL so we can read ?token
  const rawUrl = event.rawUrl || `https://${hdrs.host}${event.path}${event.rawQuery ? `?${event.rawQuery}` : ""}`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook = Boolean(token && WEBHOOK_TOKEN && token === WEBHOOK_TOKEN);

  // CORS (webhooks typically have no Origin)
  const allowedOrigin = hasOrigin && ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowedOrigin ? okCors(origin) : {};

  // OPTIONS preflight
  if (event.httpMethod === "OPTIONS") {
    log("OPTIONS preflight");
    return { statusCode: 204, headers: cors, body: "" };
  }

  // Require allowed Origin or a valid webhook token
  if (!allowedOrigin && !isWebhook) {
    log("403 Forbidden { requestOrigin:", hasOrigin ? origin : null, ", isWebhook:", isWebhook, "}");
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  // Basic env sanity check
  if (!SUPABASE_URL || !SERVICE_KEY) log("Note: REST client not fully configured");
  if (!DB_URL) log("Note: SQL pool not configured");
  try {
    if (DB_URL) {
      const u = new URL(DB_URL);
      log("DB URL user:", u.username, "| host:", u.hostname, "| ssl:", u.search || "(none)");
    }
  } catch {}

  try {
    /* ---------- Parse body ---------- */
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    const bodyStr = getBodyString(event);
    log("content-type:", ct || "(none)", "| bytes:", bodyStr.length, "| webhook:", isWebhook);

    let payload = {};
    if (ct.includes("application/json")) {
      const raw = tryJson(bodyStr) || {};
      payload = pickNetlifyData(raw);
      log("parsed json keys:", Object.keys(payload || {}));
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(bodyStr || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // multi-checkbox capture
      log("parsed form-encoded keys:", Object.keys(payload || {}));
    } else {
      // Try JSON even with missing/incorrect content-type (some services do this)
      const maybe = tryJson(bodyStr);
      if (maybe) {
        payload = pickNetlifyData(maybe);
        log("parsed json (no ct) keys:", Object.keys(payload || {}));
      } else {
        log("415 Unsupported content type");
        return { statusCode: 415, headers: cors, body: "Unsupported content type" };
      }
    }

    // Honeypot
    if (payload["bot-field"]) {
      log("honeypot hit; ignoring");
      return { statusCode: 204, headers: cors, body: "" };
    }

    /* ---------- Normalize to table schema ---------- */
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  = fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    const email = String(payload.email || "").trim();
    if (!isEmail(email) || email.toLowerCase() === "you@example.com") {
      log("invalid email:", email);
      return { statusCode: 400, headers: cors, body: "Invalid email" };
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

    const row = { first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua };
    log("inserting row (email):", email);

    /* ---------- Try REST insert first ---------- */
    if (supabase) {
      try {
        const { data, error } = await supabase.from(TABLE).insert(row).select("id").single();
        if (error) throw error;
        log("REST insert ok, id:", data?.id);
        return {
          statusCode: 200,
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
          body: JSON.stringify({ ok: true, id: data?.id ?? null, via: "rest" }),
        };
      } catch (e) {
        log("REST insert failed:", e?.message || e);
        // fall through to SQL
      }
    } else {
      log("REST client not available; skipping");
    }

    /* ---------- SQL fallback (Transaction Pooler) ---------- */
    if (!pool) {
      log("No SQL pool configured");
      return { statusCode: 502, headers: cors, body: "Supabase REST unreachable" };
    }

    const sql = `
      insert into public.${TABLE}
        (first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua)
      values
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      returning id;
    `;
    const params = [
      first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua,
    ];

    try {
      const r = await pool.query(sql, params);
      const id = r?.rows?.[0]?.id ?? null;
      log("SQL insert ok, id:", id);
      return {
        statusCode: 200,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
        body: JSON.stringify({ ok: true, id, via: "sql" }),
      };
    } catch (e) {
      log("SQL insert error:", e?.message || e);
      return { statusCode: 500, headers: cors, body: "Database insert failed" };
    }
  } catch (err) {
    log("Unhandled error:", err?.message || err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
