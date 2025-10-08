// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Allowed origins (production + preview + local if you use it)
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888" // remove if you don't use netlify dev
];

export async function handler(event) {
  try {
    // 1) Method guard
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: "Method Not Allowed" };
    }

    // 2) Origin allowlist
    const origin = event.headers.origin || event.headers.referer || "";
    if (!ALLOWED_ORIGINS.some(o => origin.startsWith(o))) {
      console.warn("Blocked origin:", origin);
      return { statusCode: 403, body: "Forbidden" };
    }

    // 3) Parse body (supports urlencoded + json)
    const ct = (event.headers["content-type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // keep all selected roles
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, body: "Unsupported content type" };
    }

    // 4) Honeypot (silent drop)
    if (payload["bot-field"]) {
      return { statusCode: 204, body: "" };
    }

    // 5) Validate inputs
    const email = (payload.email || "").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, body: "Invalid email" };
    }
    const name = (payload.name || "").trim();
    const [first_name, ...rest] = name.split(/\s+/);
    const last_name = rest.join(" ") || null;

    const role =
      Array.isArray(payload["role[]"]) && payload["role[]"].length
        ? payload["role[]"].join(", ")
        : Array.isArray(payload.role)
        ? payload.role.join(", ")
        : payload.role || null;

    // 6) Light “ping” to confirm DB connectivity
    const { error: pingErr } = await supabase.from("signups").select("id").limit(1);
    if (pingErr) {
      console.error("Supabase connection failed:", pingErr.message);
      return { statusCode: 500, body: "Database connection failed" };
    }

    // 7) Insert
    const { error: insertErr } = await supabase.from("signups").insert({
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in: payload.updates === "yes",
      ip: event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || null,
      ua: event.headers["user-agent"] || null,
      created_at: new Date().toISOString()
    });

    if (insertErr) {
      console.error("Database insert error:", insertErr.message);
      return { statusCode: 500, body: "Database insert failed" };
    }

    // 8) Success
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, body: "Server error" };
  }
}
