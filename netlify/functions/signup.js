// netlify/functions/signup.js
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

// Explicit Pool config + TLS to avoid self-signed cert errors
let pool = null;
if (DB_URL) {
  try {
    const u = new URL(DB_URL);
    pool = new Pool({
      host: u.hostname,
      port: Number(u.port) || 5432,
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: (u.pathname || "/postgres").slice(1),
      ssl: { require: true, rejectUnauthorized: false },
    });
  } catch (e) {
    console.log("[signup] DB URL parse error:", e?.message || e);
  }
}

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

  // Compose raw URL so we can read ?token
  const rawUrl = event.rawUrl || `https://${hdrs.host}${event.path}${event.rawQuery ? `?${event.rawQuery}` : ""}`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook = Boolean(token && WEBHOOK_TOKEN && token === WEBHOOK_TOKEN);

  // CORS (browser only; webhooks usually have no Origin)
  const allowedOrigin = hasOrigin && ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowedOrigin ? okCors(origin) : {};

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    log("OPTIONS preflight");
    return { statusCode: 204, headers: cors, body: "" };
  }

  // Require either allowed browser origin or valid webhook token
  if (!allowedOrigin && !isWebhook) {
    log("403 Forbidden { requestOrigin:", hasOrigin ? origin : null, ", isWebhook:", isWebhook, "}");
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  // Notes
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
      payload["role[]"] = params.getAll("role[]"); // capture multi-checkbox
      log("parsed form-encoded keys:", Object.keys(payload || {}));
    } else {
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

    /* ---------- Normalize for your table (Option B upsert) ---------- */
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  = fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    // normalize email to lowercase so dedupe works reliably
    const email = String(payload.email || "").trim().toLowerCase();
    if (!isEmail(email) || email === "you@example.com") {
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

    log("inserting/updating (email):", email);

    /* ---------- Try REST upsert first (requires unique on email; ok if it fails) ---------- */
    if (supabase) {
      try {
        const { data, error } = await supabase
          .from(TABLE)
          .upsert(
            { first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua },
            { onConflict: "email" }
          )
          .select("id")
          .single();
        if (error) throw error;
        log("REST upsert ok, id:", data?.id);
        return {
          statusCode: 200,
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
          body: JSON.stringify({ ok: true, id: data?.id ?? null, via: "rest" }),
        };
      } catch (e) {
        log("REST upsert failed:", e?.message || e);
        // fall through to SQL
      }
    } else {
      log("REST client not available; skipping");
    }

    /* ---------- SQL Option B upsert (works even without a unique constraint) ---------- */
    if (!pool) {
      log("No SQL pool configured");
      return { statusCode: 502, headers: cors, body: "Supabase REST unreachable" };
    }

    const client = await pool.connect();
    try {
      // 1) Try UPDATE first
      const rUpdate = await client.query(
        `
          update public.${TABLE}
          set first_name = $2,
              last_name  = $3,
              role       = $4,
              state      = $5,
              organization = $6,
              message    = $7,
              updates_opt_in = $8,
              ip = $9,
              ua = $10
          where email = $1
          returning id;
        `,
        [email, first_name, last_name, role, state, organization, message, updates_opt_in, ip, ua]
      );

      if (rUpdate?.rows?.length) {
        const id = rUpdate.rows[0].id;
        log("SQL update ok, id:", id);
        return {
          statusCode: 200,
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
          body: JSON.stringify({ ok: true, id, via: "sql_update" }),
        };
      }

      // 2) If no row updated, INSERT
      const rInsert = await client.query(
        `
          insert into public.${TABLE}
            (first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          returning id;
        `,
        [first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua]
      );

      const id = rInsert?.rows?.[0]?.id ?? null;
      log("SQL insert ok, id:", id);
      return {
        statusCode: 200,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
        body: JSON.stringify({ ok: true, id, via: "sql_insert" }),
      };
    } catch (e) {
      log("SQL upsert error:", e?.message || e);
      return { statusCode: 500, headers: cors, body: "Database upsert failed" };
    } finally {
      client.release();
    }
  } catch (err) {
    log("Unhandled error:", err?.message || err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
