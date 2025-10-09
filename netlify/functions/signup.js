// netlify/functions/signup.js
import { createClient } from "@supabase/supabase-js";

/**
 * DROP-IN CONFIG (adjust as needed)
 */
const TABLE = "signups";
const SITE_SLUG = "veteranverify"; // your Netlify site name before .netlify.app
const PROD_DOMAINS = ["veteranverify.net", "www.veteranverify.net"]; // your custom domains
const DEBUG = true; // flip to false when stable

// Optional: hardcoded fallback for SUPABASE_URL (env var is preferred)
const HARDCODED_SUPABASE_URL = "https://hyuawfauycyeqbhfwxx.supabase.co";

/**
 * ENV + CLIENT
 */
const SUPABASE_URL = (
  (process.env.SUPABASE_URL || HARDCODED_SUPABASE_URL || "").trim()
).replace(/\/+$/, "");

const SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || "").trim();
const WEBHOOK_TOKEN = (
  process.env.FORM_WEBHOOK_SECRET || process.env.WEBHOOK_TOKEN || ""
).trim();

const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false },
});

/**
 * HELPERS
 */
const log = (...a) => DEBUG && console.log("[signup]", ...a);

const isAllowedOrigin = (origin) => {
  try {
    const { hostname } = new URL(origin);

    // Production Netlify domain for this site
    if (hostname === `${SITE_SLUG}.netlify.app`) return true;

    // Branch & deploy-preview domains, e.g. main--site.netlify.app, deploy-preview-23--site.netlify.app
    if (hostname.endsWith(`--${SITE_SLUG}.netlify.app`)) return true;

    // Your custom domains
    if (PROD_DOMAINS.includes(hostname)) return true;

    // Local dev
    if (hostname === "localhost") return true;

    return false;
  } catch {
    return false;
  }
};

const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
const asBool = (v) => v === true || v === "true" || v === "1" || v === "yes" || v === "on";

const tryJson = (s) => { try { return JSON.parse(s); } catch { return null; } };

const getBodyString = (event) => {
  if (!event?.body) return "";
  return event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
};

// Netlify form webhook payload can be:
// { payload: { data: {...} } }  OR  { data: {...} }  OR  {...fields...}
const pickNetlifyData = (obj) => obj?.payload?.data ?? obj?.data ?? obj;

/**
 * HANDLER
 */
export async function handler(event) {
  // ALWAYS log an entry so Netlify shows something even if CORS rejects later
  console.log("[signup] invoked", {
    time: new Date().toISOString(),
    method: event.httpMethod,
    path: event.path,
  });

  const hdrs = event.headers || {};
  const origin = hdrs.origin || hdrs.Origin || hdrs.referer || hdrs.Referer || "";
  const hasOrigin = Boolean(origin);

  // Compose raw URL so we can read ?token
  const rawUrl =
    event.rawUrl ||
    `https://${hdrs.host}${event.path}${event.rawQuery ? `?${event.rawQuery}` : ""}`;
  const url = new URL(rawUrl);
  const token = url.searchParams.get("token") || url.searchParams.get("secret");
  const isWebhook = Boolean(token && WEBHOOK_TOKEN && token === WEBHOOK_TOKEN);

  // CORS headers builder (strict for POST, permissive for OPTIONS below)
  const allowedOrigin = hasOrigin && isAllowedOrigin(origin);
  const strictCors = allowedOrigin
    ? {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        Vary: "Origin",
      }
    : {};

  // OPTIONS: respond permissively so preflight doesn’t block logs during dev
  if (event.httpMethod === "OPTIONS") {
    log("OPTIONS preflight from:", origin || "(no origin)");
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": origin || "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers":
          hdrs["access-control-request-headers"] || "Content-Type",
        Vary: "Origin, Access-Control-Request-Headers",
      },
      body: "",
    };
  }

  // Gate actual POSTs: require either allowed browser origin OR a valid webhook token
  if (!allowedOrigin && !isWebhook) {
    log("Forbidden POST - allowedOrigin?", allowedOrigin, "isWebhook?", isWebhook, "origin:", origin);
    return { statusCode: 403, headers: strictCors, body: "Forbidden" };
  }

  // Validate Supabase config early with useful errors
  if (!/^https:\/\/[^/]+\.supabase\.co$/.test(SUPABASE_URL)) {
    console.error("[signup] Bad SUPABASE_URL value:", SUPABASE_URL);
    return { statusCode: 500, headers: strictCors, body: "Server misconfigured (SUPABASE_URL)" };
  }
  if (!SERVICE_KEY) {
    console.error("[signup] Missing SUPABASE_SERVICE_KEY");
    return { statusCode: 500, headers: strictCors, body: "Server misconfigured (service key)" };
  }

  try {
    // ---- Parse body ----
    const ct = String(hdrs["content-type"] || hdrs["Content-Type"] || "").toLowerCase();
    const bodyStr = getBodyString(event);
    log("content-type:", ct || "(none)", "| bytes:", bodyStr.length, "| webhook:", isWebhook);

    let payload = {};
    if (ct.includes("application/json")) {
      const raw = tryJson(bodyStr) || {};
      payload = pickNetlifyData(raw);
      log("parsed json keys:", Object.keys(payload || {}));
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(bodyStr || "");
      payload = Object.fromEntries(params);
      payload["role[]"] = params.getAll("role[]"); // capture multi-checkbox
      log("parsed form-encoded keys:", Object.keys(payload || {}));
    } else {
      // Try JSON anyway if content-type missing/wrong
      const maybe = tryJson(bodyStr);
      if (maybe) {
        payload = pickNetlifyData(maybe);
        log("parsed json (no ct) keys:", Object.keys(payload || {}));
      } else {
        log("Unsupported content type; returning 415");
        return { statusCode: 415, headers: strictCors, body: "Unsupported content type" };
      }
    }

    // Honeypot
    if (payload["bot-field"]) {
      log("honeypot hit; ignoring");
      return { statusCode: 204, headers: strictCors, body: "" };
    }

    // ---- Normalize for your table ----
    const fullName = String(payload.name || "").trim();
    const first_name = fullName ? fullName.split(/\s+/)[0] : (payload.first_name || null);
    const last_name  = fullName ? (fullName.split(/\s+/).slice(1).join(" ") || null) : (payload.last_name || null);

    const email = String(payload.email || "").trim();
    if (!isEmail(email) || email.toLowerCase() === "you@example.com") {
      log("invalid email:", email);
      return { statusCode: 400, headers: strictCors, body: "Invalid email" };
    }

    let role = null;
    if (Array.isArray(payload["role[]"]) && payload["role[]"].length) {
      role = payload["role[]"].join(", ");
    } else if (payload.role) {
      role = String(payload.role);
    }

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

    log("inserting row (email):", email);

    // ---- Insert ----
    const { data, error } = await supabase.from(TABLE).insert(row).select("id");
    if (error) {
      console.error("[signup] Supabase insert error:", JSON.stringify(error));
      return {
        statusCode: 500,
        headers: strictCors,
        body: error.message || "Database insert failed",
      };
    }

    log("inserted id:", data?.[0]?.id);
    return {
      statusCode: 200,
      headers: { ...strictCors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ ok: true, id: data?.[0]?.id ?? null }),
    };
  } catch (err) {
    console.error("[signup] Unhandled error:", err?.message || err);
    return { statusCode: 500, headers: strictCors, body: "Server error" };
  }
}
