document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form[name='vv-waitlist']");
  if (!form) return;

  const btn = form.querySelector('button[type="submit"]');
  const ok  = document.getElementById("form-success");
  let isSubmitting = false;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isSubmitting) return;
    isSubmitting = true;
    if (btn) btn.disabled = true;

    try {
      const data = new FormData(form);
      const body = new URLSearchParams([...data]).toString();

      // 1) Write to Supabase via Netlify Function
      const res = await fetch("/.netlify/functions/signup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });
      if (!res.ok) throw new Error("Function failed");

      // 2) Trigger Netlify Forms email (no page reload)
      await fetch("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      form.reset();
      if (ok) {
        ok.classList.add("show");
        ok.setAttribute("role", "alert");
        ok.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      // avoid refresh-resubmit duplicates
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
