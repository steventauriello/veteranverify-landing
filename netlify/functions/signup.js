// netlify/functions/signup.js
import { createClient } from '@supabase/supabase-js'

// === Supabase setup ===
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

export async function handler(event) {
  try {
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: 'Method Not Allowed' }
    }

    const contentType =
      (event.headers['content-type'] ||
        event.headers['Content-Type'] ||
        '').toLowerCase()

    let payload = {}
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(event.body)
      payload = Object.fromEntries(params)
      payload['role[]'] = params.get
