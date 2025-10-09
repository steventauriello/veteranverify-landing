// netlify/functions/signup.js
import { randomUUID } from "node:crypto";

// ===== CONFIG =====
const TABLE = "signups";
const ALLOWED_ORIGINS = [
  "https://veteranverify.net",
  "https://www.veteranverify.net",
  "https://veteranverify.netlify.app",
  "http://localhost:8888",
];

// allow deploy previews like https://deploy-preview-12--veteranverify.netlify.app
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

const cors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  Vary: "Origin",
});

export async function handler(event) {
  const hdrs = event.headers || {};
  const origin =
    hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";

  // Browser-originated CORS check
  const browserAllowed = isAllowedOrigin(origin);

  // Webhook token (for server→server Netlify notifications: no Origin header)
  const q = event.queryStringParameters || {};
  const token = q.token || q.TOKEN || "";
  const tokenOk = !!(process.env.WEBHOOK_TOKEN && token === process.env.WEBHOOK_TOKEN);

  const headers = browserAllowed ? cors(origin) : {};

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: "Method Not Allowed" };
  }
  // Require either a good browser Origin OR a valid webhook token
  if (!browserAllowed && !tokenOk) {
    return { statusCode: 403, body: "Forbidden" };
  }

  // Env
  const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
  const SERVICE_KEY  = (process.env.SUPABASE_SERVICE_KEY || "").trim();
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers, body: "Server misconfigured" };
  }

  try {
    // ---- Parse body ----
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    let body = {};
    if (ct.includes("application/json")) {
      body = JSON.parse(event.body || "{}");
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(event.body || "");
      body = Object.fromEntries(params);
      body["role[]"] = params.getAll("role[]");
    } else {
      return { statusCode: 415, headers, body: "Unsupported content type" };
    }

    // If it’s a Netlify form webhook, the fields live under payload.data
    const data = body?.payload?.data ?? body?.data ?? body;

    // Honeypot (works both ways; Netlify includes it in data if present)
    if (data["bot-field"]) {
      return { statusCode: 204, headers, body: "" };
    }

    // ---- Normalize fields ----
    const email = String(data.email || "").trim();
    const fullName = String(data.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (data.first_name || null);
    const last_name  =
      fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (data.last_name || null);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers, body: "Invalid email" };
    }

    // role may be "role[]" array or a single value "role"
    const rolesArray =
      Array.isArray(data["role[]"]) ? data["role[]"] :
      (typeof data.role === "string" && data.role.includes(",")) ? data.role.split(",").map(s=>s.trim()) :
      (data.role ? [data.role] : []);
    const role = rolesArray.length ? rolesArray.join(", ") : null;

    // Browser requests have real IP/UA; webhook usually doesn't
    const ip =
      hdrs["x-nf-client-connection-ip"] ||
      hdrs["client-ip"] ||
      (hdrs["x-forwarded-for"] || "").split(",")[0].trim() ||
      hdrs["x-real-ip"] ||
      body?.payload?.ip ||
      null;

    const ua = String(hdrs["user-agent"] || body?.payload?.user_agent || "");

    // ---- Row mapped to your columns ----
    const row = {
      id: randomUUID(),
      first_name,
      last_name,
      email,
      role,
      state: data.state || null,
      organization: data.organization || null,
      message: data.message || null,
      updates_opt_in:
        data.updates === "yes" ||
        data.updates === "on" ||
        data.updates === true ||
        data.updates === "true" ||
        data.updates === "1",
      ip,
      ua,
      created_at: new Date().toISOString(),
    };

    // ---- Insert via Supabase REST ----
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/${TABLE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Prefer: "return=representation",
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
      },
      body: JSON.stringify([row]),
    });

    const text = await resp.text();
    if (!resp.ok) {
      console.error("Supabase insert failed:", resp.status, text.slice(0, 500));
      return { statusCode: 500, headers, body: "Database insert failed" };
    }

    let inserted = null;
    try { inserted = JSON.parse(text); } catch {}
    return {
      statusCode: 200,
      headers: { ...headers, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true, id: inserted?.[0]?.id ?? null }),
    };
  } catch (err) {
    console.error("Unhandled error:", err);
    return { statusCode: 500, headers, body: "Server error" };
  }
}
