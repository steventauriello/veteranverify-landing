// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

const TABLE = "signups"; // change if your table name differs

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY // SERVICE ROLE key (server-side only)
);

// add/remove your exact domains here
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888" // keep only if you use `netlify dev`
];

const okCors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin",
});

export async function handler(event) {
  const origin = event.headers.origin || "";
  const allowed = ALLOWED_ORIGINS.some((o) => origin.startsWith(o));
  const cors = allowed ? okCors(origin) : {};

  // CORS preflight
  if (event.httpMethod === "OPTIONS")
    return { statusCode: 204, headers: cors, body: "" };

  if (!allowed) return { statusCode: 403, body: "Forbidden" };
  if (event.httpMethod !== "POST")
    return { statusCode: 405, headers: cors, body: "Method Not Allowed" };

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("Missing Supabase env vars");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // Parse body (form-encoded OR JSON)
    const ct = (event.headers["content-type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // if you ever use checkboxes
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot
    if (payload["bot-field"]) {
      return { statusCode: 204, headers: cors, body: "" };
    }

    // Inputs: your form may have a single "name" field; split to first/last
    const email = String(payload.email || "").trim();
    const fullName = String(payload.name || "").trim(); // if you have a single name input
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name = fullName
      ? (fullName.split(/\s+/).slice(1).join(" ") || null)
      : (payload.last_name || null);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }

    const roles = Array.isArray(payload["role[]"]) ? payload["role[]"] : [];
    const role  = roles.length ? roles.join(", ") : (payload.role || null);

    // Derive IP & UA
    const ip =
      event.headers["x-nf-client-connection-ip"] ||
      event.headers["client-ip"] ||
      (event.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      event.headers["x-real-ip"] ||
      null;

    const ua = (event.headers["user-agent"] || "").slice(0, 255);

    // EXACTLY your columns:
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
        payload.updates === "on"  ||
        payload.updates === true,
      ip,
      ua,
      created_at: new Date().toISOString(),
    };

    const { error } = await supabase.from(TABLE).insert(row);
    if (error) {
      console.error("Insert error:", error.message);
      return { statusCode: 500, headers: cors, body: "Database insert failed" };
    }

    return {
      statusCode: 200,
      headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true }),
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, headers: cors, body: "Server error" };
  }
}
