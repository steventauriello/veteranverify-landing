// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "node:crypto"; // optional: generate id in code too

// --- CONFIG ---
const TABLE = "signups";

// Domains allowed to call this function
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888" // keep only if you use `netlify dev`
];

// CORS helper
const okCors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  Vary: "Origin"
});

// --- SUPABASE SERVER CLIENT (uses Netlify env vars) ---
const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const SERVICE_KEY  = (process.env.SUPABASE_SERVICE_KEY || "").trim();

const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false }
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
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // Parse body (form-encoded or JSON)
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // collect multi-select
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot
    if (payload["bot-field"]) {
      return { statusCode: 204, headers: cors, body: "" };
    }

    // ---- Normalize & validate ----
    const email = String(payload.email || "").trim();
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name =
      fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }

    const roles = Array.isArray(payload["role[]"]) ? payload["role[]"] : [];
    const role = roles.length ? roles.join(", ") : (payload.role || null);

    const ip =
      hdrs["x-nf-client-connection-ip"] ||
      hdrs["client-ip"] ||
      (hdrs["x-forwarded-for"] || "").split(",")[0].trim() ||
      hdrs["x-real-ip"] ||
      null;

    const ua = String(hdrs["user-agent"] || "");

    // ---- Row must match your table columns exactly ----
    const row = {
      id: randomUUID(), // optional: DB also has default gen_random_uuid()
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

 // Insert and return the inserted row (so we can confirm it)
const { data, error } = await supabase
  .from(TABLE)
  .insert(row)
  .select(); // returns the new row(s)

if (error) {
  console.error("Insert error:", JSON.stringify(error));
  // Surface the reason during debugging; you can change this back to a generic message later
  return { statusCode: 500, headers: cors, body: error.message || "Database insert failed" };
}

// Success
return {
  statusCode: 200,
  headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify({ ok: true, id: data?.[0]?.id ?? null })
};

  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
