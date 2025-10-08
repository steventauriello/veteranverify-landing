// /.netlify/functions/signup.js
import { createClient } from '@supabase/supabase-js';

export default async (req, context) => {
  if (req.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY)
    return new Response('Server not configured', { status: 500 });

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // Accept your existing urlencoded form
  const ct = req.headers.get('content-type') || '';
  let payload = {};
  if (ct.includes('application/x-www-form-urlencoded')) {
    const form = await req.formData();
    payload = Object.fromEntries(form.entries());
  } else if (ct.includes('application/json')) {
    payload = await req.json();
  } else {
    return new Response('Unsupported content type', { status: 415 });
  }

  const email = (payload.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return new Response('Invalid email', { status: 400 });

  const name = (payload.name || '').trim();
  const [first_name, ...rest] = name.split(/\s+/);
  const last_name = rest.join(' ') || null;

  const role = Array.isArray(payload['role[]'])
    ? payload['role[]'].join(', ')
    : (payload.role || null);

  const { error } = await supabase.from('signups').insert({
    first_name,
    last_name,
    email,
    role,
    state: payload.state || null,
    organization: payload.organization || null,
    message: payload.message || null,
    updates_opt_in: payload.updates === 'yes',
    ip: context.ip || null,
    ua: req.headers.get('user-agent') || null
  });

  if (error) {
    console.error(error);
    return new Response('Insert failed', { status: 500 });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
};
