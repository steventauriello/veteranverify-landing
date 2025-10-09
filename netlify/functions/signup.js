// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

// Server-side Supabase client (service role; NEVER expose on client)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Allow only your domains (add/remove as needed)
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888" // keep only if you actually use netlify dev
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

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  // Method / origin checks
  if (!allowed) return { statusCode: 403, body: "Forbidden" };
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: cors, body: "Method Not Allowed" };
  }

  // Env vars check
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("Missing Supabase env vars");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // Parse body (supports form-encoded & JSON)
    const ct = (event.headers["content-type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]");
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot
    if (payload["bot-field"]) {
      return { statusCode: 204, headers: cors, body: "" };
    }

    // Validate inputs
    const email = String(payload.email || "").trim();
    const name = String(payload.name || "").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers: cors, body: "Invalid email" };
    }
    const [first_name, ...rest] = name.split(/\s+/);
    const last_name = rest.join(" ") || null;

    const roles = Array.isArray(payload["role[]"]) ? payload["role[]"] : [];
    const role = roles.length ? roles.join(", ") : (payload.role || null);

    // Insert
    const { error: insertErr } = await supabase.from("signups").insert({
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in: payload.updates === "yes",
      user_agent: (event.headers["user-agent"] || "").slice(0, 255),
      referer: (event.headers["referer"] || "").slice(0, 255),
      created_at: new Date().toISOString(),
    });

    if (insertErr) {
      console.error("Database insert error:", insertErr.message);
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
