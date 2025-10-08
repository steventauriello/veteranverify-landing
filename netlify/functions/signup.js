// netlify/functions/signup.js
import { createClient } from '@supabase/supabase-js'

// === Supabase setup ===
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

export async function handler(event) {
  try {
    // === 1️⃣ Basic method validation ===
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: 'Method Not Allowed' }
    }

    const contentType =
      (event.headers['content-type'] ||
        event.headers['Content-Type'] ||
        '').toLowerCase()

    let payload = {}

    // === 2️⃣ Parse request body safely ===
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(event.body)
      payload = Object.fromEntries(params)
      payload['role[]'] = params.getAll('role[]') // preserve multi-checkbox
    } else if (contentType.includes('application/json')) {
      payload = JSON.parse(event.body || '{}')
    } else {
      return { statusCode: 415, body: 'Unsupported content type' }
    }

    // === 3️⃣ Honeypot spam trap ===
    if (payload['bot-field']) {
      return { statusCode: 204, body: '' } // silently ignore bots
    }

    // === 4️⃣ Basic validation ===
    const email = (payload.email || '').trim()
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, body: 'Invalid email' }
    }

    const name = (payload.name || '').trim()
    const [first_name, ...rest] = name.split(/\s+/)
    const last_name = rest.join(' ') || null

    // combine roles properly
    const role =
      Array.isArray(payload['role[]']) && payload['role[]'].length
        ? payload['role[]'].join(', ')
        : Array.isArray(payload.role)
        ? payload.role.join(', ')
        : payload.role || null

    // === 5️⃣ Insert into Supabase ===
    const { error } = await supabase.from('signups').insert({
      first_name,
      last_name,
      email,
      role,
      state: payload.state || null,
      organization: payload.organization || null,
      message: payload.message || null,
      updates_opt_in: payload.updates === 'yes',
      ip:
        event.headers['x-nf-client-connection-ip'] ||
        event.headers['client-ip'] ||
        null,
      ua: event.headers['user-agent'] || null,
      created_at: new Date().toISOString()
    })

    if (error) {
      console.error('Supabase insert error:', error)
      return { statusCode: 500, body: 'Database insert failed' }
    }

    // === 6️⃣ Success response ===
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      },
      body: JSON.stringify({ ok: true })
    }
  } catch (err) {
    console.error('Function error:', err)
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' })
    }
  }
}
