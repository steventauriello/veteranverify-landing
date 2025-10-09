// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

// ---- CONFIG ----
const TABLE = "signups";

// Allow your site origins for browser CORS
const ALLOWED_ORIGINS = [
  "https://veteranverify.netlify.app",
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "http://localhost:8888", // keep if you use `netlify dev`
];

// Build CORS headers
const okCors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  Vary: "Origin",
});

// Supabase (server-side) client
const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || "").trim();

const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false },
});

// Helpers
const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
const asBool = (v) =>
  v === true || v === "true" || v === "1" || v === "yes" || v === "on";

// Safely parse JSON
const tryJson = (s) => {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};

// Decode body if Netlify passed it base64-encoded
const getBodyString = (event) => {
  if (!event?.body) return "";
  return event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
};

export async function handler(event) {
  const headers = event.headers || {};
  const origin =
    headers.origin || headers.Origin || headers.referer || headers.Referer || "";
  const hasOrigin = !!origin;

  // Figure out the full URL to read the webhook token
  const rawUrl =
    event.rawUrl ||
    `https://${headers.host}${event.path}${
      event.rawQuery ? `?${event.rawQuery}` : ""
    }`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook =
    !!token && !!process.env.WEBHOOK_TOKEN && token === process.env.WEBHOOK_TOKEN;

  // CORS for browser requests only (webhooks generally have no Origin)
  const allowedOrigin =
    hasOrigin && ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowedOrigin ? okCors(origin) : {};

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  // Require authorized context: either allowed browser origin OR valid webhook token
  if (!allowedOrigin && !isWebhook) {
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  // Basic env guardrails
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // ---- Parse body (form-encoded, JSON, or Netlify form webhook JSON) ----
    const ct = String(headers["content-type"] || headers["Content-Type"] || "").toLowerCase();
    const bodyStr = getBodyString(event);
    let payload = {};

    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(bodyStr || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // capture multi-checkbox
    } else if (ct.includes("application/json")) {
      const raw = tryJson(bodyStr) || {};
      // Netlify Form Webhook shape: { payload: { data: {...}, ... } }
      payload = raw?.payload?.data ?? raw;
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot (if present)
    if (payload["bot-field"]) {
      return { statusCode: 204, headers: cors, body: "" };
    }

    // ---- Normalize fields for your signups table ----
    // Your form uses single "name"; split into first/last if possible
    const fullName = String(payload.name || "").trim();
    const first_name = fullName
      ? fullName.split(/\s+/)[0]
      : (payload.first_name || null);
    const last_name = fullName
      ? (fullName.split(/\s+/).slice(1).join(" ") || null)
      : (payload.last_name || null);

    const email = String(payload.email || "").trim();
    if (!isEmail(email) || email.toLowerCase() === "you@example.com") {
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }

    // role: either array (role[]) or single value (role)
    let role = null;
    if (Array.isArray(payload["role[]"]) && payload["role[]"].length) {
      role = payload["role[]"].join(", ");
    } else if (payload.role) {
      role = String(payload.role);
    }

    // Optional extras
    const state = payload.state || null;
    const organization = payload.organization || null;
    const message = payload.message || null;
    const updates_opt_in =
      asBool(payload.updates) || asBool(payload.updates_opt_in);

    // IP & UA (best-effort)
    const ip =
      headers["x-nf-client-connection-ip"] ||
      headers["client-ip"] ||
      (headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      headers["x-real-ip"] ||
      null;

    const ua = String(headers["user-agent"] || "");

    // Build row – let DB defaults set id & created_at
    const row = {
      first_name,
      last_name,
      email,
      role,
      state,
      organization,
      message,
      updates_opt_in,
      ip,
      ua,
    };

    // ---- Insert ----
    const { data, error } = await supabase.from(TABLE).insert(row).select("id");
    if (error) {
      console.error("Supabase insert error:", error);
      // Surface the reason while debugging; swap to a generic message later if you want
      return {
        statusCode: 500,
        headers: cors,
        body: error.message || "Database insert failed",
      };
    }

    // Success
    return {
      statusCode: 200,
      headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true, id: data?.[0]?.id ?? null }),
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
