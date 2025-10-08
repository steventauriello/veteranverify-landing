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

  // 🟡 NEW tiny polish — prevents accidental double submissions
  let isSubmitting = false;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isSubmitting) return;   // ignore double clicks
    isSubmitting = true;
    if (btn) btn.disabled = true;

    const data = new FormData(form);
    const body = new URLSearchParams([...data]).toString();

    try {
      // 1️⃣ Save to your Netlify Function (Supabase, etc.)
      const res = await fetch("/.netlify/functions/signup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });
      if (!res.ok) throw new Error("Function failed");

      // 2️⃣ Also ping Netlify Forms (email alert) — AJAX only, no reload
      await fetch("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      // ✅ Success UX
      form.reset();
      if (ok) {
        ok.style.display = "block";
        ok.classList.add("show");
        ok.setAttribute("role", "alert");
        ok.scrollIntoView({ behavior: "smooth", block: "center" });
      }

      // ✅ Prevent refresh-email issue
      history.replaceState(null, "", window.location.pathname);
    } catch (err) {
      console.error(err);
      alert("⚠️ Something went wrong. Please try again later.");
    } finally {
      isSubmitting = false;
      if (btn) btn.disabled = false;
    }
  });
});