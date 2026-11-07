const $ = (selector) => document.querySelector(selector);

function csrfToken() {
  const token = document.cookie.split("; ").find((cookie) => cookie.startsWith("scc_csrf="))?.slice(9) || "";
  return decodeURIComponent(token);
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes((options.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
  const result = await response.json().catch(() => ({}));
  if (response.status === 401) {
    window.location.replace("/login");
    throw new Error("Please sign in again.");
  }
  if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
  return result;
}

document.querySelectorAll("[data-tab]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-tab]").forEach((tab) => {
      const selected = tab === button;
      tab.setAttribute("aria-selected", String(selected));
      document.getElementById(tab.dataset.tab).classList.toggle("active", selected);
    });
  });
});

async function loadConfig() {
  try {
    const config = await api("/api/minecraft/config");
    $("#rcon-host").value = config.host;
    $("#rcon-port").value = config.port;
    $("#rcon-password").required = !config.configured;
    $("#clear-rcon").hidden = !config.configured;
    $("#rcon-config-result").textContent = config.configured
      ? "An encrypted connection is saved for this account. Re-enter its password to replace the settings."
      : "No RCON connection is saved for this account.";
    await loadStatus();
  } catch (error) {
    $("#rcon-config-result").textContent = error.message;
  }
}

async function loadStatus() {
  $("#mc-status").textContent = "Checking the saved RCON connection…";
  try {
    const data = await api("/api/minecraft/status");
    $("#mc-status").textContent = data.online
      ? `Connected to ${data.address} · ${data.message || "Server responded"}`
      : data.message || "Not connected";
  } catch (error) {
    $("#mc-status").textContent = error.message;
  }
}

$("#rcon-config").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = $("#rcon-config-result");
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  result.textContent = "Saving encrypted connection…";
  try {
    await api("/api/minecraft/config", {
      method: "PUT",
      body: JSON.stringify({
        host: $("#rcon-host").value.trim(),
        port: Number($("#rcon-port").value),
        password: $("#rcon-password").value || null,
      }),
    });
    $("#rcon-password").value = "";
    $("#rcon-password").required = false;
    $("#clear-rcon").hidden = false;
    result.textContent = "RCON settings saved to your account.";
    await loadStatus();
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#clear-rcon").addEventListener("click", async () => {
  if (!window.confirm("Remove this account's saved Minecraft RCON connection?")) return;
  try {
    await api("/api/minecraft/config", { method: "DELETE" });
    $("#rcon-host").value = "";
    $("#rcon-port").value = "25575";
    $("#rcon-password").value = "";
    $("#rcon-password").required = true;
    $("#clear-rcon").hidden = true;
    $("#rcon-config-result").textContent = "Saved RCON connection removed.";
    await loadStatus();
  } catch (error) {
    $("#rcon-config-result").textContent = error.message;
  }
});

$("#refresh").addEventListener("click", loadStatus);

$("#moderate").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = $("#moderation-result");
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  result.textContent = "Sending moderation action…";
  try {
    const data = await api("/api/minecraft/moderate", {
      method: "POST",
      body: JSON.stringify({
        action: $("#action").value,
        player: $("#player").value.trim(),
        reason: $("#reason").value.trim(),
      }),
    });
    result.textContent = data.response;
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#search-mods").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = $("#mod-query").value.trim();
  if (!query) return;
  const box = $("#mod-results");
  box.textContent = "Searching…";
  try {
    const facets = JSON.stringify([["project_type:mod"]]);
    const response = await fetch(
      `https://api.modrinth.com/v2/search?limit=10&query=${encodeURIComponent(query)}&facets=${encodeURIComponent(facets)}`,
      { credentials: "omit" },
    );
    if (!response.ok) throw new Error("Modrinth search is currently unavailable.");
    const data = await response.json();
    box.replaceChildren();
    for (const hit of data.hits || []) {
      const card = document.createElement("article");
      card.className = "mod-card";
      const info = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = hit.title;
      const description = document.createElement("small");
      description.textContent = hit.description;
      info.append(title, description);
      const link = document.createElement("a");
      link.href = `https://modrinth.com/mod/${encodeURIComponent(hit.slug)}`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "View";
      card.append(info, link);
      box.append(card);
    }
    if (!box.childElementCount) box.textContent = "No matching mods found.";
  } catch (error) {
    box.textContent = error.message;
  }
});

$("#mc-signout").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } finally {
    window.location.replace("/");
  }
});

loadConfig();
