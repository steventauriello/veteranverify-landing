// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Allowed domains (add your production + preview)
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888"
];

export async function handler(event) {
  try {
    // --- 1️⃣ Guard HTTP method
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: "Method Not Allowed" };
    }

    // --- 2️⃣ Guard Origin
    const origin = event.headers.origin || event.headers.referer || "";
    if (!ALLOWED_ORIGINS.some((o) => origin.startsWith(o))) {
      console.warn("Rejected origin:", origin);
      return { statusCode: 403, body: "Forbidden" };
    }

    // --- 3️⃣ Validate Content Type
    const ct = (event.headers["content-type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      payload = Object.fromEntries(new URLSearchParams(event.body));
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, body: "Unsupported content type" };
    }

    // --- 4️⃣ Basic field validation
    const email = (payload.email || "").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, body: "Invalid email" };
    }
    const name = (payload.name || "").trim();
    const [first_name, ...rest] = name.split(/\s+/);
    const last_name = rest.join(" ") || null;
    const role = Array.isArray(payload["role[]"])
      ? payload["role[]"].join(", ")
      : payload.role || null;

    // --- 5️⃣ Test Supabase connection (light ping)
    const { error: pingErr } = await supabase.from("signups").select("id").limit(1);
    if (pingErr) {
      console.error("Supabase connection failed:", pingErr.message);
      return { statusCode: 500, body: "Database connection failed" };
    }

    // --- 6️⃣ Insert new record
    const { error: insertErr } = await supabase.from("signups").insert({
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in: payload.updates === "yes",
      ip:
        event.headers["x-nf-client-connection-ip"] ||
        event.headers["client-ip"] ||
        null,
      ua: event.headers["user-agent"] || null,
      created_at: new Date().toISOString()
    });

    if (insertErr) {
      console.error("Database insert error:", insertErr.message);
      return { statusCode: 500, body: "Database insert failed" };
    }

    // --- 7️⃣ Respond success
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, body: "Server error" };
  }
}
