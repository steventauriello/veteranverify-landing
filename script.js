document.addEventListener("DOMContentLoaded", () => {
  // Keep the Learn More button functionality
  const btn = document.getElementById("learnMoreBtn");
  if (btn) {
    btn.addEventListener("click", () => {
      alert("Veteran Verify is under construction — stay tuned!");
    });
  }

  // Add the signup form submission handler
  const form = document.querySelector("form[name='vv-waitlist']");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const data = new FormData(form);

    try {
      const res = await fetch("/.netlify/functions/signup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams([...data]).toString(),
      });

      if (!res.ok) throw new Error("Bad response");

      form.reset();
      alert("✅ Thank you for signing up! You’re on the Veteran Verify list.");
    } catch (err) {
      console.error(err);
      alert("⚠️ Something went wrong. Please try again later.");
    }
  });
});