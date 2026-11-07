function csrfToken() {
  const token = document.cookie.split("; ").find((cookie) => cookie.startsWith("scc_csrf="))?.slice(9) || "";
  return decodeURIComponent(token);
}

fetch("/api/auth/me", { credentials: "same-origin" })
  .then((response) => {
    if (!response.ok) window.location.replace("/login");
  })
  .catch(() => window.location.replace("/login"));

document.getElementById("hub-signout").addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrfToken() },
    });
  } finally {
    window.location.replace("/");
  }
});
