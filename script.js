document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form[name="vv-waitlist"]');
  const successEl = document.getElementById('form-success');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    payload['role[]'] = fd.getAll('role[]');

    const btn = form.querySelector('button[type="submit"]');
    const prev = btn ? btn.textContent : null;
    if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }

    try {
      // 1️⃣  Send to Supabase
      const res = await fetch('/.netlify/functions/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const txt = await res.text();
      if (!res.ok) throw new Error(txt || `HTTP ${res.status}`);

      // 2️⃣  Ghost ping to Netlify Forms for email notification only
      const ghost = new URLSearchParams();
      ghost.append('form-name', 'vv-waitlist');
      ghost.append('message', 'New signup submitted on VeteranVerify.net');

      fetch('/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: ghost.toString()
      });

      // 3️⃣  Show success + auto-scroll
      if (successEl) {
        successEl.textContent = "Thanks—you're on the list!";
        successEl.classList.add('show');
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
      form.reset();
    } catch (err) {
      console.error('Submit failed:', err);
      alert('Sorry, something went wrong. Please try again.');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = prev; }
    }
  });
});