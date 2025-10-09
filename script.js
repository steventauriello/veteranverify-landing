document.addEventListener("DOMContentLoaded", () => {
  // script.js
const form = document.querySelector('form[name="vv-waitlist"]');
const successEl = document.getElementById('form-success');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = new URLSearchParams([...new FormData(form)]).toString();

  try {
    const res = await fetch('/.netlify/functions/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    const text = await res.text();            // <-- show what the function returned
    if (!res.ok) {
      console.error('Function error:', res.status, text);
      alert(text || 'Function failed');       // <-- you'll see the DB reason here
      return;
    }

    successEl.textContent = "Thanks—you're on the list!";
    successEl.classList.add('show');
    form.reset();
  } catch (err) {
    console.error(err);
    alert('Network error');
  }
});
