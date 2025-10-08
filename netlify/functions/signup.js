// netlify/functions/signup.js
import { createClient } from '@supabase/supabase-js'

// ---- Supabase setup ----
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

export async function handler(event) {
  try {
    // 1) Method check
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: 'Method Not Allowed' }
    }

    // 2) Parse body
    const contentType =
      (event.headers['content-type'] || event.headers['Content-Type'] || '').toLowerCase()

    let payload = {}
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(event.body || '')
      payload = Object.fromEntries(params)
      payload['role[]'] = params.getAll('role[]') // preserve multi-checkbox values
    } else if (contentType.includes('application/json')) {
      payload = JSON.parse(event.body || '{}')
    } else {
      return { statusCode: 415, body: 'Unsupported content type' }
    }

    // 3) Honeypot
    if (payload['bot-field']) {
      // silent no-op for bots
      return { statusCode: 204, body: '' }
    }

    // 4) Validate inputs (min)
    const email = (payload.email || '').trim()
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, body: 'Invalid email' }
    }

    const name = (payload.name || '').trim()
    const [first_name, ...rest] = name.split(/\s+/)
    const last_name = rest.join(' ') || null

    const role =
      Array.isArray(payload['role[]']) && payload['role[]'].length
        ? payload['role[]'].join(', ')
        : Array.isArray(payload.role)
        ? payload.role.join(', ')
        : (payload.role || null)

    // 5) Insert
    const insertRow = {
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
    }

    const { error } = await supabase.from('signups').insert(insertRow)

    if (error) {
      // ---- DEBUG OUTPUT (TEMPORARY) ----
      console.error('Supabase insert error:', JSON.stringify(error, null, 2))
      console.error('Tried to insert row:', JSON.stringify(insertRow, null, 2))
      return {
        statusCode: 500,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({ ok: false, stage: 'insert', error })
      }
    }

    // 6) Success
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ ok: true })
    }
  } catch (err) {
    // ---- DEBUG OUTPUT (TEMPORARY) ----
    console.error('Function error:', err)
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: false, stage: 'handler', error: String(err) })
    }
  }
}
