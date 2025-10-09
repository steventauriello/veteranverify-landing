// netlify/functions/signup.js
import { randomUUID } from "node:crypto";

// ======= CONFIG =======
const TABLE = "signups";
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888", // keep only if you use `netlify dev`
];

// allow Netlify deploy previews like https://deploy-preview-12--veteranverify.netlify.app
function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.some((o) => origin.startsWith(o))) return true;
  try {
    const host = new URL(origin).hostname;
    return /^deploy-preview-\d+--veteranverify\.netlify\.app$/.test(host);
  } catch {
    return false;
  }
}

const corsHeaders = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  Vary: "Origin",
});

// ======= HANDLER =======
export async function handler(event) {
  const hdrs = event.headers || {};
  const origin = hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";
  const allowed = isAllowedOrigin(origin);
  const cors = allowed ? corsHeaders(origin) : {};

  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };
  if (!allowed) return { statusCode: 403, body: "Forbidden" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: cors, body: "Method Not Allowed" };

  // Clean env (trim & remove trailing slashes)
  const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
  const SERVICE_KEY  = (process.env.SUPABASE_SERVICE_KEY || "").trim();
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers: cors, body: "Server misconfigured" };
  }

  try {
    // ---- Parse body (form-encoded or JSON) ----
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    let payload = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // collect multi-select checkboxes
    } else if (ct.includes("application/json")) {
      payload = JSON.parse(event.body || "{}");
    } else {
      return { statusCode: 415, headers: cors, body: "Unsupported content type" };
    }

    // Honeypot
    if (payload["bot-field"]) return { statusCode: 204, headers: cors, body: "" };

    // ---- Normalize & validate ----
    const email = String(payload.email || "").trim();
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  =
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

    // ---- Build row to match your columns exactly ----
    // Columns: id (uuid), first_name, last_name, email, role, state, organization,
    //          message, updates_opt_in (bool), ip, ua, created_at (timestamp)
    const row = {
      id: randomUUID(), // DB also has default; this is a belt-and-suspenders
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
      created_at: new Date().toISOString(),
    };

    // ---- Insert via Supabase REST (PostgREST) ----
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/${TABLE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Prefer": "return=representation",
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
      },
      body: JSON.stringify([row]), // array form = bulk insert API; returns inserted rows
    });

    const text = await resp.text();

    if (!resp.ok) {
      console.error("Supabase insert failed:", resp.status, text.slice(0, 500));
      return { statusCode: 500, headers: cors, body: "Database insert failed" };
    }

    let data = null;
    try { data = JSON.parse(text); } catch {}

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
