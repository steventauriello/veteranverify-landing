// netlify/functions/signup.js
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

export async function handler(event) {
  try {
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: 'Method Not Allowed' }
    }

    const ct = (event.headers['content-type'] || event.headers['Content-Type'] || '').toLowerCase()
    let payload = {}
    if (ct.includes('application/x-www-form-urlencoded')) {
      payload = Object.fromEntries(new URLSearchParams(event.body))
    } else if (ct.includes('application/json')) {
      payload = JSON.parse(event.body || '{}')
    } else {
      return { statusCode: 415, body: 'Unsupported content type' }
    }

    const email = (payload.email || '').trim()
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, body: 'Invalid email' }
    }

    const name = (payload.name || '').trim()
    const [first_name, ...rest] = name.split(/\s+/)
    const last_name = rest.join(' ') || null
    const role = Array.isArray(payload['role[]'])
      ? payload['role[]'].join(', ')
      : (payload.role || null)

    const { error } = await supabase.from('signups').insert({
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in: payload.updates === 'yes',
      ip: event.headers['x-nf-client-connection-ip'] || event.headers['client-ip'] || null,
      ua: event.headers['user-agent'] || null,
      created_at: new Date().toISOString()
    })
// netlify/functions/signup.js
    if (error) {
      console.error('Supabase insert error:', error)
      return { statusCode: 500, body: 'Insert failed' }
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true })
    }
  } catch (err) {
    console.error('Function error:', err)
    return { statusCode: 500, body: 'Server error' }
  }
}
