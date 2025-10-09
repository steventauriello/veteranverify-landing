// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

// --- CONFIG ---
// Your Supabase table name:
const TABLE = "signups";

// Domains allowed to call this function (edit to match your live domains)
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  // keep this only if you still use your Netlify preview domain:
  "https://veteranverify.netlify.app",
  // keep only if you use `netlify dev` locally:
  "http://localhost:8888"
];

// --- SUPABASE SERVER CLIENT (uses Netlify env vars) ---
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY // service_role key (server-side only)
);

// Small helper to build CORS headers
const okCors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin"
});

export async function handler(event) {
  const hdrs = event.headers || {};
  const origin =
    hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";

  const allowed = ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowed ? okCors(origin) : {};

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  // Guardrails
  if (!allowed) return { statusCode: 403, body: "Forbidden" };
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: cors, body: "Method Not Allowed" };
  }
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // Parse body (supports form-encoded & JSON)
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "")
      .toLowerCase();

    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      // capture multi-select checkboxes like role[]
      payload["role[]"] = params.getAll("role[]");
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot (anti-bot)
    if (payload["bot-field"]) {
      return { statusCode: 204, headers: cors, body: "" };
    }

    // ---- Normalize & validate inputs ----
    const email = String(payload.email || "").trim();
    const fullName = String(payload.name || "").trim(); // if your form uses a single "name" field
    const first_name = fullName
      ? fullName.split(/\s+/)[0]
      : (payload.first_name || null);
    const last_name = fullName
      ? (fullName.split(/\s+/).slice(1).join(" ") || null)
      : (payload.last_name || null);

    // simple email check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }

    // role could be array (role[]) or single value (role)
    const roles = Array.isArray(payload["role[]"]) ? payload["role[]"] : [];
    const role = roles.length ? roles.join(", ") : (payload.role || null);

    // derive IP & UA for your `ip` and `ua` columns
    const ip =
      hdrs["x-nf-client-connection-ip"] ||
      hdrs["client-ip"] ||
      (hdrs["x-forwarded-for"] || "").split(",")[0].trim() ||
      hdrs["x-real-ip"] ||
      null;

    const ua = String(hdrs["user-agent"] || "").slice(0, 255);

    // ---- Build row EXACTLY to your columns ----
    // Columns you told me you have:
    // id (uuid, default), first_name, last_name, email, role, state,
    // organization, message, updates_opt_in (bool), ip, ua, created_at
    const row = {
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in:
        payload.updates === "yes" ||
        payload.updates === "on" ||
        payload.updates === true ||
        payload.updates === "true" ||
        payload.updates === "1",
      ip,
      ua,
      created_at: new Date().toISOString()
    };

    // Insert
    const { error } = await supabase.from(TABLE).insert(row);
    if (error) {
      console.error("Database insert error:", error.message);
      return { statusCode: 500, headers: cors, body: "Database insert failed" };
    }

    return {
      statusCode: 200,
      headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
