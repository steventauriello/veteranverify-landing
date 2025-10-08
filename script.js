document.addEventListener("DOMContentLoaded", () => {
  // (optional) keep your Learn More button
  const lm = document.getElementById("learnMoreBtn");
  if (lm) {
    lm.addEventListener("click", () => {
      alert("Veteran Verify is under construction — stay tuned!");
    });
  }

  const form = document.querySelector("form[name='vv-waitlist']");
  if (!form) return;

  const btn = form.querySelector('button[type="submit"]');
  const ok  = document.getElementById("form-success");

  // Footer year (nice to have)
  const yr = document.getElementById("yr");
  if (yr) yr.textContent = new Date().getFullYear();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const data = new FormData(form);
    const body = new URLSearchParams([...data]).toString();
    if (btn) btn.disabled = true;

    try {
      // 1) Save to your Netlify Function (Supabase, etc.)
      const res = await fetch("/.netlify/functions/signup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });
      if (!res.ok) throw new Error("Function failed");

      // 2) Also ping Netlify Forms so you still get the email (AJAX; no navigation)
      await fetch("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      // Success UX: reset, reveal banner, fade & scroll
      form.reset();
      if (ok) {
        ok.style.display = "block";
        ok.classList.add("show");
        ok.setAttribute("role", "alert");
        ok.scrollIntoView({ behavior: "smooth", block: "center" });
      }

      // Prevent any accidental POST-in-history from causing refresh emails
      history.replaceState(null, "", window.location.pathname);
    } catch (err) {
      console.error(err);
      // (No classic form.submit() fallback — avoids POST/refresh loops)
      alert("⚠️ Something went wrong. Please try again later.");
    } finally {
      if (btn) btn.disabled = false;
    }
  });
});
