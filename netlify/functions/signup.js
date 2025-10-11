// netlify/functions/signup.js
// ESM ("type":"module" in package.json)

// --- TEMP DEBUG ENV CHECK ---
console.log("[signup] ENV CHECK:", {
  url_ok: !!process.env.SUPABASE_URL,
  key_len: process.env.SUPABASE_SERVICE_KEY?.length || 0,
  db_ok: !!process.env.SUPABASE_DB_URL
});

import { createClient } from "@supabase/supabase-js";
import * as dns from "node:dns";

try { dns.setDefaultResultOrder?.("ipv4first"); } catch {}

const TABLE = "signups";
const ALLOWED_ORIGINS = [
  "https://veteranverify.netlify.app",
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "http://localhost:8888",
  "http://127.0.0.1:8888",
];
const DEBUG = true;

// -------- ENVs ----------
const SUPABASE_URL  = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const SERVICE_KEY   = (process.env.SUPABASE_SERVICE_KEY || "").trim();
const WEBHOOK_TOKEN = (process.env.FORM_WEBHOOK_SECRET || process.env.WEBHOOK_TOKEN || "").trim();

const supabase = (SUPABASE_URL && SERVICE_KEY)
  ? createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } })
  : null;

// -------- Helpers ----------
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
const getBodyString = (event) => event?.isBase64Encoded
  ? Buffer.from(event.body || "", "base64").toString("utf8")
  : (event?.body || "");

// Map alternate field names (safe no-ops if absent)
const applyFieldAliases = (p) => {
  p.name         ??= p.fullname ?? p.full_name ?? null;
  p.email        ??= p.user_email ?? p.contact_email ?? null;
  p.organization ??= p.company ?? p.org ?? null;
  p.message      ??= p.notes ?? p.comment ?? null;
  p.state        ??= p.region ?? p.province ?? null;
  return p;
};

// -------- Handler ----------
export async function handler(event) {
  const hdrs = event.headers || {};
  const origin = hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";
  const hasOrigin = Boolean(origin);

  const rawUrl = event.rawUrl || `https://${hdrs.host}${event.path}${event.rawQuery ? `?${event.rawQuery}` : ""}`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook = Boolean(token && WEBHOOK_TOKEN && token === WEBHOOK_TOKEN);

  const allowedOrigin = hasOrigin && ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowedOrigin ? okCors(origin) : {};

  if (event.httpMethod === "OPTIONS") {
    log("OPTIONS preflight");
    return { statusCode: 204, headers: cors, body: "" };
  }

  if (!allowedOrigin && !isWebhook) {
    log("403 Forbidden { requestOrigin:", hasOrigin ? origin : null, ", isWebhook:", isWebhook, "}");
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  if (!SUPABASE_URL || !SERVICE_KEY) {
    log("REST client not fully configured");
    return { statusCode: 500, headers: cors, body: "Server config error" };
  }

  try {
    // ---- Parse body
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    const bodyStr = getBodyString(event);
    log("content-type:", ct || "(none)", "| bytes:", bodyStr.length, "| webhook:", isWebhook);

    let payload = {};
    if (ct.includes("application/json")) {
      payload = tryJson(bodyStr) || {};
      payload = payload?.payload?.data ?? payload?.data ?? payload; // Netlify webhook shapes
      log("parsed json keys:", Object.keys(payload || {}));
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(bodyStr || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]");
      log("parsed form-encoded keys:", Object.keys(payload || {}));
    } else {
      const maybe = tryJson(bodyStr);
      if (maybe) {
        payload = maybe?.payload?.data ?? maybe?.data ?? maybe;
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

    // Apply alias mapping, normalize
    payload = applyFieldAliases(payload);

    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  = fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    const email = String(payload.email || "").trim();
    if (!isEmail(email) || email.toLowerCase() === "you@example.com") {
      log("invalid email:", email);
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }

    let role = null;
    if (Array.isArray(payload["role[]"]) && payload["role[]"].length) role = payload["role[]"].join(", ");
    else if (payload.role) role = String(payload.role);

    const state          = payload.state || null;
    const organization   = payload.organization || null;
    const message        = payload.message || null;
    const updates_opt_in = asBool(payload.updates) || asBool(payload.updates_opt_in);

    const ip =
      hdrs["x-nf-client-connection-ip"] ||
      hdrs["client-ip"] ||
      (hdrs["x-forwarded-for"] || "").split(",")[0].trim() ||
      hdrs["x-real-ip"] || null;

    const ua = String(hdrs["user-agent"] || "");

    const row = { first_name, last_name, email, role, state, organization, message, updates_opt_in, ip, ua };
    log("row about to write:", JSON.stringify(row));

    // ---- REST upsert (authoritative path) ----
    try {
      const { data, error } = await supabase
        .from(TABLE)
        .upsert(row, { onConflict: "email" })
        .select("id, email, first_name, last_name, role, state, organization, message, updates_opt_in, created_at")
        .single();
      if (error) throw error;
      log("REST upsert ok, id:", data?.id);
      return {
        statusCode: 200,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
        body: JSON.stringify({ ok: true, via: "rest_upsert", ...data }),
      };
    } catch (e) {
      log("REST upsert failed:", e?.message || e);
      return {
        statusCode: 502,
        headers: { ...cors, "Content-Type": "application/json" },
        body: JSON.stringify({ ok: false, via: "rest_error", error: e?.message || String(e) }),
      };
    }

  } catch (err) {
    log("Unhandled error:", err?.message || err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}