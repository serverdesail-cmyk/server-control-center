const PERMISSION_LABELS = {
  browse: "browse", read: "read", download: "download", upload: "upload",
  create: "create", edit: "edit", rename: "rename", delete: "delete",
};
const PERMISSION_PRESETS = {
  read: ["browse", "read", "download"],
  contribute: ["browse", "read", "download", "upload", "create", "edit", "rename"],
  full: Object.keys(PERMISSION_LABELS),
};

const THEMES = {
  Midnight: { background: "#0c0e13", surface: "#131720", sidebar: "#10131b", primary: "#8c7cff", text: "#edf0f7", muted: "#9299aa", border: "#262c39" },
  Cyberpunk: { background: "#0c0715", surface: "#171024", sidebar: "#110b1c", primary: "#fa44d3", text: "#f8ecff", muted: "#a99ab9", border: "#33213d" },
  Glassmorphism: { background: "#111827", surface: "#18243a", sidebar: "#131d30", primary: "#53c7ec", text: "#edf7ff", muted: "#9badc1", border: "#2b3c53" },
  Professional: { background: "#111519", surface: "#181f25", sidebar: "#141a20", primary: "#57a9e8", text: "#eaf0f4", muted: "#9ba8b1", border: "#2a343c" },
  Minimal: { background: "#151515", surface: "#1d1d1d", sidebar: "#191919", primary: "#c5c5c5", text: "#f3f3f3", muted: "#a1a1a1", border: "#383838" },
  AMOLED: { background: "#000000", surface: "#090909", sidebar: "#050505", primary: "#8d7aff", text: "#f3f3f5", muted: "#9a9aa3", border: "#24242a" },
};

const state = {
  user: null,
  path: "/",
  items: [],
  folderPermissions: [],
  grid: false,
  editorPath: null,
  originalText: "",
  resetUserId: null,
  uploadRequest: null,
  theme: "Midnight",
  metricsTimer: null,
  activityTimer: null,
  activeView: "dashboard",
  activityRows: [],
  lastServerActivity: [],
  logFilter: "all",
  metricsSample: null,
  activeRoot: null,
  mountRoot: null,
  rootPickerPath: null,
  rootPickerParent: null,
  workspacePreferences: null,
};

const MENU_ITEMS = [
  { key: "dashboard", view: "dashboard", label: "Overview", required: true },
  { key: "files", view: "files", label: "Files" },
  { key: "monitoring", view: "monitoring", label: "Monitoring" },
  { key: "access", view: "access", label: "Access control", ownerOnly: true },
  { key: "logs", view: "logs", label: "Logs" },
  { key: "settings", view: "appearance", label: "Settings", required: true },
];
const DEFAULT_MENU_ORDER = MENU_ITEMS.map((item) => item.key);

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("show"), 3600);
}

function csrfToken() {
  return document.cookie.split("; ").find((cookie) => cookie.startsWith("scc_csrf="))?.slice(9) || "";
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) headers.set("X-CSRF-Token", decodeURIComponent(csrfToken()));
  const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
  if (response.status === 401) {
    showAuth();
    throw new Error("Please sign in again.");
  }
  const type = response.headers.get("content-type") || "";
  const result = type.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) throw new Error(result.detail || result || `Request failed (${response.status})`);
  return result;
}

function showAuth() {
  state.user = null;
  clearInterval(state.metricsTimer);
  clearInterval(state.activityTimer);
  state.metricsSample = null;
  $("#app-shell").hidden = true;
  $("#auth-view").hidden = false;
  $("#auth-form").reset();
  api("/api/setup/status").then(({ owner_exists }) => {
    const setup = !owner_exists;
    $("#auth-title").textContent = setup ? "Set up your server" : "Welcome back";
    $("#auth-description").textContent = setup
      ? "Create the Root_user account to secure your server workspace."
      : "Sign in to your server workspace.";
    $("#auth-submit").textContent = setup ? "Create Root_user account" : "Sign in";
    $("#setup-token-label").hidden = !setup;
    $("#auth-password").autocomplete = setup ? "new-password" : "current-password";
    $("#auth-hint").textContent = setup
      ? "Get the one-time token on the server with: sudo scc setup-token"
      : "Sessions expire automatically and can be revoked by Root_user.";
    $("#auth-form").dataset.setup = String(setup);
  }).catch((error) => toast(error.message, true));
}

function showApp(user) {
  state.user = user;
  $("#auth-view").hidden = true;
  $("#app-shell").hidden = false;
  $("#profile-name").textContent = user.username;
  $("#profile-role").textContent = roleLabel(user.role);
  $("#avatar-letter").textContent = user.username.slice(0, 1).toUpperCase();
  $$(".owner-only").forEach((el) => { el.hidden = user.role !== "owner"; });
  loadWorkspacePreferences();
  loadProfile();
  recordClientActivity("session_started");
  navigate("dashboard");
  loadDashboard();
  startMetricsPolling();
  startActivityPolling();
}

function roleLabel(role) {
  return role === "owner" ? "ROOT_USER" : role.toUpperCase();
}

async function bootstrap() {
  try {
    const user = await api("/api/auth/me");
    showApp(user);
  } catch {
    showAuth();
  }
}

function navigate(view) {
  const previousView = state.activeView;
  state.activeView = view;
  $$(".view").forEach((element) => { element.hidden = element.id !== `${view}-view`; });
  $$(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.nav === view));
  const titles = {
    dashboard: ["SERVER OVERVIEW", "Overview"],
    files: ["FILE MANAGEMENT", "Files"],
    monitoring: ["SERVER HEALTH", "Monitoring"],
    access: ["ROOT_USER CONTROL", "Access control"],
    logs: ["ACTIVITY", "Logs"],
    appearance: ["WORKSPACE", "Settings"],
  };
  const [eyebrow, title] = titles[view] || titles.dashboard;
  $("#section-eyebrow").textContent = eyebrow;
  $("#section-title").textContent = title;
  if (view === "files") loadFiles(state.path);
  if (view === "access" && state.user?.role === "owner") loadAdmin();
  if (view === "monitoring") loadMetrics();
  if (view === "logs") loadActivity();
  if (view === "appearance") loadProfile();
  if (state.user && view !== previousView) recordClientActivity("page_opened", view);
}

function clientActivityKey() {
  return `scc-browser-activity:${state.user.id}`;
}

function readClientActivity() {
  try {
    const records = JSON.parse(localStorage.getItem(clientActivityKey()) || "[]");
    if (!Array.isArray(records)) throw new Error("Stored activity is not a list.");
    return records.filter((row) => row && typeof row.action === "string" && Number.isFinite(row.created_at));
  } catch (error) {
    try {
      localStorage.removeItem(clientActivityKey());
      toast(`This browser's saved activity could not be read and was cleared: ${error.message}`, true);
    } catch (storageError) {
      toast(`This browser's saved activity could not be read or cleared: ${storageError.message}`, true);
    }
    return [];
  }
}

function recordClientActivity(action, detail = "") {
  if (!state.user) return;
  const records = readClientActivity();
  records.unshift({
    source: "browser",
    username: state.user.username,
    action,
    detail,
    created_at: Date.now() / 1000,
  });
  try {
    localStorage.setItem(clientActivityKey(), JSON.stringify(records.slice(0, 100)));
  } catch (error) {
    toast(`Could not save this browser's activity: ${error.message}`, true);
  }
  if (state.activeView === "logs") {
    state.activityRows = combineActivity(state.lastServerActivity);
    renderLogActivity();
  } else if (state.activeView === "dashboard") {
    renderActivity(combineActivity(state.lastServerActivity).slice(0, 8), $("#activity-list"));
  }
}

function combineActivity(serverRows) {
  return [...serverRows.map((row) => ({ ...row, source: "server" })), ...readClientActivity()]
    .sort((left, right) => right.created_at - left.created_at);
}

function loadWorkspacePreferences() {
  const key = `scc-workspace:${state.user.id}`;
  try {
    const saved = JSON.parse(localStorage.getItem(key) || "null");
    const validKeys = new Set(MENU_ITEMS.filter((item) => !item.ownerOnly || state.user.role === "owner").map((item) => item.key));
    const order = Array.isArray(saved?.order)
      ? [...new Set(saved.order.filter((item) => validKeys.has(item))), ...DEFAULT_MENU_ORDER.filter((item) => validKeys.has(item) && !saved.order.includes(item))]
      : DEFAULT_MENU_ORDER.filter((item) => validKeys.has(item));
    const visible = Array.isArray(saved?.visible)
      ? saved.visible.filter((item) => validKeys.has(item))
      : [...validKeys];
    state.workspacePreferences = { order, visible: [...new Set([...visible, "dashboard", "settings"])] };
  } catch {
    state.workspacePreferences = {
      order: DEFAULT_MENU_ORDER.filter((item) => !MENU_ITEMS.find((entry) => entry.key === item).ownerOnly || state.user.role === "owner"),
      visible: DEFAULT_MENU_ORDER.filter((item) => !MENU_ITEMS.find((entry) => entry.key === item).ownerOnly || state.user.role === "owner"),
    };
    toast("Saved workspace menu settings could not be read; defaults were restored.", true);
  }
  applyWorkspacePreferences();
  renderMenuSettings();
}

function saveWorkspacePreferences() {
  applyWorkspacePreferences();
  renderMenuSettings();
  try {
    localStorage.setItem(`scc-workspace:${state.user.id}`, JSON.stringify(state.workspacePreferences));
    recordClientActivity("menu_preferences_changed");
  } catch (error) {
    toast(`Could not save workspace menu settings: ${error.message}`, true);
  }
}

function applyWorkspacePreferences() {
  const nav = $(".main-nav");
  if (!nav || !state.workspacePreferences) return;
  const items = new Map($$(".nav-item", nav).map((item) => [item.dataset.menuKey, item]));
  for (const key of state.workspacePreferences.order) {
    const item = items.get(key);
    if (item) nav.append(item);
  }
  for (const menu of MENU_ITEMS) {
    const element = items.get(menu.key);
    if (element) {
      element.hidden = Boolean(menu.ownerOnly && state.user?.role !== "owner")
        || (!menu.required && !state.workspacePreferences.visible.includes(menu.key));
    }
  }
}

function reorderMenuItem(sourceKey, targetKey) {
  if (!sourceKey || !targetKey || sourceKey === targetKey) return;
  const order = [...state.workspacePreferences.order];
  const sourceIndex = order.indexOf(sourceKey);
  const targetIndex = order.indexOf(targetKey);
  if (sourceIndex < 0 || targetIndex < 0) return;
  order.splice(targetIndex, 0, ...order.splice(sourceIndex, 1));
  state.workspacePreferences.order = order;
  saveWorkspacePreferences();
}

function renderMenuSettings() {
  const container = $("#menu-settings-list");
  if (!container || !state.workspacePreferences) return;
  container.replaceChildren();
  for (const key of state.workspacePreferences.order) {
    const menu = MENU_ITEMS.find((item) => item.key === key);
    if (!menu || (menu.ownerOnly && state.user?.role !== "owner")) continue;
    const row = document.createElement("div");
    row.className = "menu-setting-row";
    const label = document.createElement("span");
    label.className = "menu-setting-label";
    label.textContent = menu.label;
    const visible = document.createElement("label");
    visible.className = "menu-visibility";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.workspacePreferences.visible.includes(key) || Boolean(menu.required);
    checkbox.disabled = Boolean(menu.required);
    checkbox.addEventListener("change", () => {
      const current = new Set(state.workspacePreferences.visible);
      if (checkbox.checked) current.add(key);
      else current.delete(key);
      state.workspacePreferences.visible = [...current];
      saveWorkspacePreferences();
    });
    visible.append(checkbox, document.createTextNode(" Show"));
    const controls = document.createElement("span");
    controls.className = "menu-order-controls";
    const index = state.workspacePreferences.order.indexOf(key);
    for (const [direction, title, offset] of [["up", "Move up", -1], ["down", "Move down", 1]]) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button secondary menu-order-button";
      button.textContent = direction === "up" ? "↑" : "↓";
      button.title = title;
      button.setAttribute("aria-label", `${title}: ${menu.label}`);
      button.disabled = index + offset < 0 || index + offset >= state.workspacePreferences.order.length;
      button.addEventListener("click", () => {
        const other = state.workspacePreferences.order[index + offset];
        reorderMenuItem(key, other);
      });
      controls.append(button);
    }
    row.append(label, visible, controls);
    container.append(row);
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${mins}m` : `${mins}m`;
}

async function loadDashboard() {
  try {
    const data = await api("/api/dashboard");
    state.lastServerActivity = data.recent_activity;
    $("#disk-used").textContent = `${formatBytes(data.disk.used)} / ${formatBytes(data.disk.total)}`;
    $("#disk-caption").textContent = `${formatBytes(data.disk.free)} available`;
    $("#disk-meter").style.width = `${Math.min(100, data.disk.total ? data.disk.used / data.disk.total * 100 : 0)}%`;
    $("#uptime").textContent = formatDuration(data.uptime_seconds);
    $("#app-version").textContent = `v${data.version}`;
    $("#footer-version").textContent = data.version;
    $("#root-path").textContent = data.filesystem_root;
    $("#mount-root").textContent = data.filesystem_mount_root;
    state.activeRoot = data.filesystem_root;
    state.mountRoot = data.filesystem_mount_root;
    $("#sessions").textContent = data.active_sessions ?? "—";
    renderActivity(combineActivity(state.lastServerActivity).slice(0, 8), $("#activity-list"));
  } catch (error) { toast(error.message, true); }
}

function percentage(value, total) {
  return total > 0 ? Math.min(100, Math.max(0, value / total * 100)) : 0;
}

function formatRate(bytesPerSecond) {
  return `${formatBytes(bytesPerSecond)}/s`;
}

async function loadMetrics() {
  try {
    const data = await api("/api/system/metrics");
    const previous = state.metricsSample;
    const elapsed = previous
      ? Math.max(0.001, (data.sampled_at - previous.sampledAt))
      : 0;
    const receivedRate = previous
      ? Math.max(0, (data.network.received_bytes - previous.received) / elapsed)
      : null;
    const transmittedRate = previous
      ? Math.max(0, (data.network.transmitted_bytes - previous.transmitted) / elapsed)
      : null;
    state.metricsSample = {
      sampledAt: data.sampled_at,
      received: data.network.received_bytes,
      transmitted: data.network.transmitted_bytes,
    };

    const cpu = data.cpu_percent;
    setProgressRing("#cpu-ring", "#cpu-ring-value", cpu, cpu === null ? "—" : `${cpu.toFixed(0)}%`);
    $("#cpu-value").textContent = cpu === null ? "Sampling…" : `${cpu.toFixed(1)}%`;
    $("#cpu-caption").textContent = cpu === null ? "Collecting first host sample" : "Total server utilization";
    $("#cpu-meter").style.width = `${cpu ?? 0}%`;
    $("#monitor-cpu").textContent = cpu === null ? "Sampling…" : `${cpu.toFixed(1)}%`;
    $("#monitor-cpu-meter").style.width = `${cpu ?? 0}%`;
    $("#monitor-cpu-ring").style.setProperty("--progress", `${cpu ?? 0}%`);
    $("#monitor-cpu-ring-value").textContent = cpu === null ? "—" : `${cpu.toFixed(0)}%`;
    $("#monitor-load").textContent = `Load average · ${data.load_average.map((value) => value.toFixed(2)).join(" / ")}`;

    const memoryPercent = percentage(data.memory.used, data.memory.total);
    setProgressRing("#memory-ring", "#memory-ring-value", memoryPercent, `${memoryPercent.toFixed(0)}%`);
    $("#memory-used").textContent = `${formatBytes(data.memory.used)} / ${formatBytes(data.memory.total)}`;
    $("#memory-caption").textContent = `${memoryPercent.toFixed(1)}% used · ${formatBytes(data.memory.available)} available`;
    $("#memory-meter").style.width = `${memoryPercent}%`;
    $("#monitor-memory").textContent = `${formatBytes(data.memory.used)} / ${formatBytes(data.memory.total)}`;
    $("#monitor-memory-meter").style.width = `${memoryPercent}%`;
    $("#monitor-memory-ring").style.setProperty("--progress", `${memoryPercent}%`);
    $("#monitor-memory-ring-value").textContent = `${memoryPercent.toFixed(0)}%`;
    $("#monitor-memory-free").textContent = `${formatBytes(data.memory.available)} available · ${memoryPercent.toFixed(1)}% used`;

    $("#uptime").textContent = formatDuration(data.uptime_seconds);
    $("#load-caption").textContent = `Load ${data.load_average.map((value) => value.toFixed(2)).join(" · ")}`;
    $("#monitor-uptime").textContent = formatDuration(data.uptime_seconds);
    $("#metrics-updated").textContent = `Updated ${new Date(data.sampled_at * 1000).toLocaleTimeString()}`;
    $("#metrics-status").textContent = "LIVE";
    $("#metrics-status").classList.add("online");
    $("#monitor-rx").textContent = `↓ ${receivedRate === null ? "…" : formatRate(receivedRate)}`;
    $("#monitor-tx").textContent = `↑ ${transmittedRate === null ? "…" : formatRate(transmittedRate)}`;
    $("#monitor-network-total").textContent =
      `${formatBytes(data.network.received_bytes)} received · ${formatBytes(data.network.transmitted_bytes)} sent since boot`;
  } catch (error) {
    state.metricsSample = null;
    $("#metrics-status").textContent = "UNAVAILABLE";
    $("#metrics-status").classList.remove("online");
    $("#cpu-value").textContent = "Unavailable";
    $("#cpu-caption").textContent = "Host telemetry unavailable";
    $("#cpu-meter").style.width = "0";
    setProgressRing("#cpu-ring", "#cpu-ring-value", 0, "—");
    $("#memory-used").textContent = "Unavailable";
    $("#memory-caption").textContent = "Host telemetry unavailable";
    $("#memory-meter").style.width = "0";
    setProgressRing("#memory-ring", "#memory-ring-value", 0, "—");
    $("#monitor-cpu").textContent = "Unavailable";
    $("#monitor-cpu-meter").style.width = "0";
    $("#monitor-cpu-ring").style.setProperty("--progress", "0%");
    $("#monitor-cpu-ring-value").textContent = "—";
    $("#monitor-memory").textContent = "Unavailable";
    $("#monitor-memory-free").textContent = "Host telemetry unavailable";
    $("#monitor-memory-meter").style.width = "0";
    $("#monitor-memory-ring").style.setProperty("--progress", "0%");
    $("#monitor-memory-ring-value").textContent = "—";
    $("#monitor-uptime").textContent = "Unavailable";
    $("#monitor-rx").textContent = "↓ —";
    $("#monitor-tx").textContent = "↑ —";
    $("#monitor-network-total").textContent = "Host telemetry unavailable";
    $("#metrics-updated").textContent = error.message || "Host telemetry unavailable";
  }
}

function startMetricsPolling() {
  clearInterval(state.metricsTimer);
  loadMetrics();
  state.metricsTimer = setInterval(() => {
    if (document.visibilityState === "visible" && state.user) loadMetrics();
  }, 5000);
}

function setProgressRing(ringSelector, valueSelector, value, label) {
  $(ringSelector).style.setProperty("--progress", `${Math.min(100, Math.max(0, value ?? 0))}%`);
  $(valueSelector).textContent = label;
}

function renderActivity(rows, list) {
  list.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Activity will appear here as you use the workspace.";
    list.append(empty);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = `activity-item ${row.source === "browser" ? "browser-activity-item" : "server-activity-item"}`;
    const dot = document.createElement("i");
    dot.className = "activity-marker";
    const text = document.createElement("span");
    text.className = "activity-text";
    text.textContent = `${row.username || "System"} · ${row.action.replaceAll("_", " ")}${row.path ? ` · ${row.path}` : ""}${row.detail ? ` · ${row.detail}` : ""}`;
    const source = document.createElement("span");
    source.className = `activity-source ${row.source}`;
    source.textContent = row.source === "browser" ? "THIS DEVICE" : "SERVER";
    const timeLabel = document.createElement("time");
    timeLabel.className = "activity-time";
    timeLabel.dateTime = new Date(row.created_at * 1000).toISOString();
    timeLabel.textContent = new Date(row.created_at * 1000).toLocaleTimeString();
    timeLabel.title = new Date(row.created_at * 1000).toLocaleString();
    item.append(dot, text, source, timeLabel);
    list.append(item);
  }
}

function startActivityPolling() {
  clearInterval(state.activityTimer);
  state.activityTimer = setInterval(() => {
    if (document.visibilityState !== "visible" || !state.user) return;
    if (state.activeView === "dashboard") loadDashboard();
    else if (state.activeView === "logs") loadActivity();
  }, 10_000);
}

function renderAvatar(avatar) {
  const picture = $("#profile-avatar");
  const preview = $("#profile-preview-image");
  const hasPicture = Boolean(avatar);
  picture.hidden = !hasPicture;
  preview.hidden = !hasPicture;
  $("#avatar-letter").hidden = hasPicture;
  $("#profile-preview-letter").hidden = hasPicture;
  if (hasPicture) {
    picture.src = avatar;
    preview.src = avatar;
  } else {
    picture.removeAttribute("src");
    preview.removeAttribute("src");
  }
}

async function loadProfile() {
  if (!state.user) return;
  try {
    const profile = await api("/api/profile");
    $("#profile-customizer-name").textContent = `${profile.username} · ${roleLabel(profile.role)}`;
    $("#profile-preview-letter").textContent = profile.username.slice(0, 1).toUpperCase();
    renderAvatar(profile.avatar);
  } catch (error) {
    toast(error.message, true);
  }
}

async function optimizeProfilePicture(file) {
  if (!file.type.startsWith("image/")) throw new Error("Choose a supported image file.");
  if (file.size > 8 * 1024 * 1024) throw new Error("Choose an image smaller than 8 MB.");
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const side = 256;
    const scale = Math.max(side / image.naturalWidth, side / image.naturalHeight);
    const width = image.naturalWidth * scale;
    const height = image.naturalHeight * scale;
    const canvas = document.createElement("canvas");
    canvas.width = side;
    canvas.height = side;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Your browser could not process this image.");
    context.drawImage(image, (side - width) / 2, (side - height) / 2, width, height);
    for (const quality of [0.88, 0.76, 0.64, 0.52, 0.4]) {
      const result = canvas.toDataURL("image/jpeg", quality);
      if (result.length <= 175_000) return result;
    }
    throw new Error("Could not reduce this image below 128 KiB.");
  } finally {
    URL.revokeObjectURL(url);
  }
}

function renderBreadcrumbs(path) {
  const crumbs = $("#breadcrumbs");
  crumbs.replaceChildren();
  const root = document.createElement("button");
  root.textContent = "root";
  root.className = path === "/" ? "current" : "";
  root.addEventListener("click", () => loadFiles("/"));
  crumbs.append(root);
  const parts = path.split("/").filter(Boolean);
  for (let index = 0; index < parts.length; index += 1) {
    const separator = document.createElement("span");
    separator.className = "breadcrumb-sep";
    separator.textContent = "/";
    const button = document.createElement("button");
    button.textContent = parts[index];
    button.className = index === parts.length - 1 ? "current" : "";
    button.addEventListener("click", () => loadFiles(`/${parts.slice(0, index + 1).join("/")}`));
    crumbs.append(separator, button);
  }
}

async function loadFiles(path) {
  state.path = path;
  try {
    if (path === "/" && state.user?.role !== "owner") {
      const { paths } = await api("/api/files/roots");
      if (!paths.length) {
        state.items = [];
        state.folderPermissions = [];
        renderBreadcrumbs("/");
        $("#file-list").replaceChildren();
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.textContent = "Root_user has not granted access to a folder yet.";
        $("#file-list").append(empty);
        $("#file-count").textContent = "No accessible folders";
        return;
      }
      if (!paths.includes("/")) path = paths[0];
    }
    const data = await api(`/api/files?path=${encodeURIComponent(path)}`);
    state.path = data.path;
    state.items = data.items;
    state.folderPermissions = data.permissions;
    renderBreadcrumbs(data.path);
    renderFiles();
    recordClientActivity("folder_opened");
  } catch (error) { toast(error.message, true); }
}

function renderFiles() {
  const container = $("#file-list");
  container.replaceChildren();
  container.classList.toggle("grid-mode", state.grid);
  const header = document.createElement("div");
  header.className = "file-header";
  for (const title of ["NAME", "SIZE", "MODIFIED", "ACTIONS"]) {
    const cell = document.createElement("span");
    cell.textContent = title;
    header.append(cell);
  }
  container.append(header);
  const needle = $("#file-filter").value.trim().toLocaleLowerCase();
  const visible = state.items.filter((item) => item.name.toLocaleLowerCase().includes(needle));
  $("#file-count").textContent = `${visible.length} item${visible.length === 1 ? "" : "s"}`;
  if (!visible.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = needle ? "No matching items in this folder." : "This folder is empty.";
    container.append(empty);
    return;
  }
  for (const item of visible) container.append(makeFileRow(item));
}

function makeFileRow(item) {
  const row = document.createElement("div");
  row.className = "file-row";
  const name = document.createElement("div");
  name.className = "file-name";
  const glyph = document.createElement("span");
  glyph.className = `file-glyph ${item.kind}`;
  glyph.textContent = item.kind === "folder" ? "▰" : item.kind === "link" ? "↗" : "▤";
  const title = document.createElement("button");
  title.textContent = item.name;
  title.title = item.name;
  if (item.kind === "folder") {
    title.addEventListener("click", () => loadFiles(`${state.path === "/" ? "" : state.path}/${item.name}`));
  } else if (item.kind === "file" && item.access.includes("read")) {
    title.title = `${item.name} · double-click to open`;
    title.addEventListener("dblclick", () => openEditor(item));
  } else if (item.access.includes("download")) {
    title.addEventListener("click", () => downloadFile(item));
  }
  name.append(glyph, title);
  const size = document.createElement("span");
  size.className = "muted";
  size.textContent = item.kind === "folder" ? "—" : formatBytes(item.size);
  const modified = document.createElement("span");
  modified.className = "muted";
  modified.textContent = new Date(item.modified).toLocaleString();
  const actions = document.createElement("div");
  actions.className = "file-actions";
  addAction(
    actions,
    "i",
    "Details",
    () => toast(`${item.permissions} · UID ${item.uid} · GID ${item.gid} · ${formatBytes(item.size)}`),
  );
  if (item.kind === "file" && item.access.includes("download")) addAction(actions, "↓", "Download", () => downloadFile(item));
  if (item.kind === "file" && item.access.includes("read")) {
    const canEdit = item.access.includes("edit");
    addAction(actions, canEdit ? "✎" : "◉", canEdit ? "Edit text file" : "Read text file", () => openEditor(item));
  }
  if (item.access.includes("rename")) addAction(actions, "✎", "Rename", () => renameFile(item));
  if (item.access.includes("delete")) addAction(actions, "×", "Delete", () => deleteFile(item));
  row.append(name, size, modified, actions);
  return row;
}

function addAction(parent, glyph, label, action) {
  const button = document.createElement("button");
  button.textContent = glyph;
  button.title = label;
  button.setAttribute("aria-label", label);
  button.addEventListener("click", action);
  parent.append(button);
}

function downloadFile(item) {
  const path = `${state.path === "/" ? "" : state.path}/${item.name}`;
  const link = document.createElement("a");
  link.href = `/api/files/download?path=${encodeURIComponent(path)}`;
  link.download = item.name;
  document.body.append(link);
  link.click();
  link.remove();
}

async function openEditor(item) {
  const path = `${state.path === "/" ? "" : state.path}/${item.name}`;
  try {
    const data = await api(`/api/files/read?path=${encodeURIComponent(path)}`);
    state.editorPath = data.path;
    state.originalText = data.content;
    $("#editor-title").textContent = item.name;
    $("#editor-content").value = data.content;
    const canEdit = item.access.includes("edit");
    $("#editor-content").readOnly = !canEdit;
    $("#editor-save").hidden = !canEdit;
    $("#editor-mode").textContent = canEdit ? "UTF-8 · Editable" : "UTF-8 · Read only";
    $("#editor-dialog").showModal();
    recordClientActivity("text_file_opened");
  } catch (error) { toast(error.message, true); }
}

$("#editor-save").addEventListener("click", async (event) => {
  event.preventDefault();
  if ($("#editor-content").value === state.originalText) {
    $("#editor-dialog").close();
    return;
  }
  if (!confirm("Save changes to this file?")) return;
  try {
    await api("/api/files/write", { method: "PUT", body: JSON.stringify({ path: state.editorPath, content: $("#editor-content").value }) });
    state.originalText = $("#editor-content").value;
    $("#editor-dialog").close();
    recordClientActivity("text_file_saved");
    toast("File saved.");
  } catch (error) { toast(error.message, true); }
});

$("#editor-content").addEventListener("keydown", (event) => {
  if (event.key === "Tab") {
    event.preventDefault();
    const input = event.currentTarget;
    const start = input.selectionStart;
    const end = input.selectionEnd;
    input.setRangeText("  ", start, end, "end");
  }
});

async function makeFolder() {
  const name = prompt("New folder name");
  if (name === null) return;
  try {
    await api("/api/files/mkdir", { method: "POST", body: JSON.stringify({ path: state.path, name }) });
    toast("Folder created.");
    await loadFiles(state.path);
  } catch (error) { toast(error.message, true); }
}

async function makeFile() {
  const name = prompt("New file name");
  if (name === null) return;
  try {
    await api("/api/files/create", { method: "POST", body: JSON.stringify({ path: `${state.path === "/" ? "" : state.path}/${name}`, content: "" }) });
    toast("File created.");
    await loadFiles(state.path);
  } catch (error) { toast(error.message, true); }
}

async function renameFile(item) {
  const name = prompt("Rename to", item.name);
  if (name === null || name === item.name) return;
  try {
    await api("/api/files/rename", { method: "POST", body: JSON.stringify({ path: `${state.path === "/" ? "" : state.path}/${item.name}`, name }) });
    toast("Renamed.");
    await loadFiles(state.path);
  } catch (error) { toast(error.message, true); }
}

async function deleteFile(item) {
  if (!confirm(`Delete "${item.name}"? This cannot be undone.`)) return;
  try {
    await api("/api/files/delete", { method: "POST", body: JSON.stringify({ path: `${state.path === "/" ? "" : state.path}/${item.name}` }) });
    toast("Deleted.");
    await loadFiles(state.path);
  } catch (error) { toast(error.message, true); }
}

function uploadFiles(files) {
  const selected = [...files];
  if (!selected.length) return;
  const form = new FormData();
  form.append("file", selected[0], selected[0].name);
  const request = new XMLHttpRequest();
  state.uploadRequest = request;
  $("#upload-progress").hidden = false;
  $("#upload-label").textContent = `Uploading ${selected[0].name}`;
  $("#upload-meter").value = 0;
  request.open("POST", `/api/files/upload?path=${encodeURIComponent(state.path)}`);
  request.withCredentials = true;
  request.setRequestHeader("X-CSRF-Token", decodeURIComponent(csrfToken()));
  request.upload.onprogress = (event) => {
    if (event.lengthComputable) $("#upload-meter").value = Math.round(event.loaded / event.total * 100);
  };
  request.onload = async () => {
    state.uploadRequest = null;
    $("#upload-progress").hidden = true;
    if (request.status >= 200 && request.status < 300) {
      toast(`Uploaded ${selected[0].name}.`);
      await loadFiles(state.path);
      if (selected.length > 1) uploadFiles(selected.slice(1));
    } else {
      let message = `Upload failed (${request.status})`;
      try { message = JSON.parse(request.responseText).detail || message; } catch { /* Response may be plain text. */ }
      toast(message, true);
    }
  };
  request.onerror = () => {
    state.uploadRequest = null;
    $("#upload-progress").hidden = true;
    toast("Upload failed due to a network error.", true);
  };
  request.onabort = () => {
    state.uploadRequest = null;
    $("#upload-progress").hidden = true;
    toast("Upload canceled.");
  };
  request.send(form);
}

$("#upload-input").addEventListener("change", (event) => {
  uploadFiles(event.currentTarget.files);
  event.currentTarget.value = "";
});
$("#cancel-upload").addEventListener("click", () => state.uploadRequest?.abort());
$("#new-folder").addEventListener("click", makeFolder);
$("#new-file").addEventListener("click", makeFile);
$("#file-filter").addEventListener("input", renderFiles);
$("#list-view").addEventListener("click", () => { state.grid = false; $("#list-view").classList.add("active"); $("#grid-view").classList.remove("active"); renderFiles(); });
$("#grid-view").addEventListener("click", () => { state.grid = true; $("#grid-view").classList.add("active"); $("#list-view").classList.remove("active"); renderFiles(); recordClientActivity("file_view_changed", "grid"); });
$("#drop-zone").addEventListener("dragover", (event) => { event.preventDefault(); event.currentTarget.classList.add("dragging"); });
$("#drop-zone").addEventListener("dragleave", (event) => event.currentTarget.classList.remove("dragging"));
$("#drop-zone").addEventListener("drop", (event) => {
  event.preventDefault();
  event.currentTarget.classList.remove("dragging");
  if (state.folderPermissions.includes("upload")) uploadFiles(event.dataTransfer.files);
  else toast("You do not have upload permission for this folder.", true);
});

async function loadAdmin() {
  try {
    const [users, grants, filesystem] = await Promise.all([
      api("/api/users"),
      api("/api/grants"),
      api("/api/owner/filesystem"),
    ]);
    renderUsers(users);
    renderGrants(grants);
    state.activeRoot = filesystem.active_root;
    state.mountRoot = filesystem.mount_root;
    $("#filesystem-root-input").value = filesystem.active_root;
    $("#filesystem-mount-label").textContent = filesystem.mount_root;
  } catch (error) { toast(error.message, true); }
}

async function loadFilesystemPicker(path) {
  try {
    const query = path ? `?path=${encodeURIComponent(path)}` : "";
    const data = await api(`/api/owner/filesystem${query}`);
    state.rootPickerPath = data.path;
    state.rootPickerParent = data.parent;
    $("#filesystem-picker-path").textContent = data.path;
    $("#filesystem-picker-up").disabled = !data.parent;
    $("#filesystem-truncated").hidden = !data.truncated;
    const list = $("#filesystem-directory-list");
    list.replaceChildren();
    if (!data.directories.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No subfolders in this directory.";
      list.append(empty);
    }
    for (const directory of data.directories) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "filesystem-directory";
      button.textContent = directory.name;
      button.addEventListener("click", () => loadFilesystemPicker(directory.path));
      list.append(button);
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadActivity() {
  try {
    const serverRows = await api("/api/activity?limit=100");
    state.lastServerActivity = serverRows;
    state.activityRows = combineActivity(serverRows);
    renderLogActivity();
  } catch (error) { toast(error.message, true); }
}

function renderLogActivity() {
  const rows = state.activityRows.filter((row) => state.logFilter === "all" || row.source === state.logFilter);
  renderActivity(rows, $("#full-activity-list"));
}

$$("[data-log-filter]").forEach((button) => button.addEventListener("click", () => {
  state.logFilter = button.dataset.logFilter;
  $$("[data-log-filter]").forEach((tab) => {
    const selected = tab === button;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  renderLogActivity();
}));

$("#clear-browser-activity").addEventListener("click", () => {
  if (!state.user || !confirm("Clear activity saved only in this browser? Server audit records will not be changed.")) return;
  try {
    localStorage.removeItem(clientActivityKey());
    state.activityRows = combineActivity(state.lastServerActivity);
    renderLogActivity();
    toast("This browser's activity was cleared. Server audit records were unchanged.");
  } catch (error) {
    toast(`Could not clear this browser's activity: ${error.message}`, true);
  }
});

$("#profile-picture-input").addEventListener("change", async (event) => {
  const file = event.currentTarget.files[0];
  if (!file) return;
  const button = event.currentTarget.closest("label");
  button.setAttribute("aria-busy", "true");
  try {
    const avatar = await optimizeProfilePicture(file);
    await api("/api/profile", { method: "PUT", body: JSON.stringify({ avatar }) });
    renderAvatar(avatar);
    recordClientActivity("profile_picture_changed");
    toast("Profile picture updated.");
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.removeAttribute("aria-busy");
    event.currentTarget.value = "";
  }
});

$("#profile-picture-remove").addEventListener("click", async () => {
  try {
    await api("/api/profile", { method: "PUT", body: JSON.stringify({ avatar: null }) });
    renderAvatar(null);
    recordClientActivity("profile_picture_removed");
    toast("Profile picture removed.");
  } catch (error) {
    toast(error.message, true);
  }
});

$("#filesystem-browse").addEventListener("click", async () => {
  await loadFilesystemPicker(state.activeRoot);
  $("#filesystem-dialog").showModal();
});
$("#filesystem-dialog-close").addEventListener("click", () => $("#filesystem-dialog").close());
$("#filesystem-picker-up").addEventListener("click", async () => {
  if (state.rootPickerParent) await loadFilesystemPicker(state.rootPickerParent);
});
$("#filesystem-picker-select").addEventListener("click", () => {
  $("#filesystem-root-input").value = state.rootPickerPath;
  $("#filesystem-dialog").close();
});
$("#filesystem-root-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const path = $("#filesystem-root-input").value.trim();
  if (!path) return;
  if (path !== state.activeRoot && !confirm("Change the active filesystem root? Grants outside the new root will be removed.")) return;
  const button = $("#filesystem-root-save");
  button.disabled = true;
  try {
    const result = await api("/api/owner/filesystem-root", {
      method: "POST",
      body: JSON.stringify({ path }),
    });
    state.activeRoot = result.filesystem_root;
    $("#filesystem-root-input").value = result.filesystem_root;
    toast(`Filesystem root updated. ${result.remapped_grants} grant(s) remapped; ${result.removed_grants} removed.`);
    await Promise.all([loadDashboard(), loadAdmin()]);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});

function renderUsers(users) {
  const container = $("#user-list");
  container.replaceChildren();
  const select = $("#grant-user");
  select.replaceChildren();
  for (const user of users.filter((item) => item.role !== "owner")) {
    const option = document.createElement("option");
    option.value = user.id;
    option.textContent = `${user.username} (${user.role})`;
    select.append(option);
  }
  updateGrantScope();
  const table = document.createElement("table");
  table.className = "admin-table";
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const label of ["Account", "Role", "State", "Actions"]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    headerRow.append(cell);
  }
  head.append(headerRow);
  const body = document.createElement("tbody");
  for (const user of users) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = user.username;
    const role = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "role-pill";
    pill.textContent = roleLabel(user.role);
    role.append(pill);
    const active = document.createElement("td");
    active.textContent = user.active ? "Active" : "Disabled";
    const actions = document.createElement("td");
    if (user.role !== "owner") {
      const toggle = document.createElement("button");
      toggle.className = "text-button";
      toggle.textContent = user.active ? "Disable" : "Enable";
      toggle.addEventListener("click", () => setUserActive(user, !user.active));
      const reset = document.createElement("button");
      reset.className = "text-button";
      reset.textContent = "Reset password";
      reset.addEventListener("click", () => resetUserPassword(user));
      const remove = document.createElement("button");
      remove.className = "text-button";
      remove.textContent = "Delete";
      remove.addEventListener("click", () => deleteUser(user));
      actions.append(toggle, document.createTextNode(" · "), reset, document.createTextNode(" · "), remove);
    } else actions.textContent = "Protected";
    row.append(name, role, active, actions);
    body.append(row);
  }
  table.append(head, body);
  container.append(table);
}

async function setUserActive(user, active) {
  try {
    await api(`/api/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ active }) });
    toast(active ? "Account enabled." : "Account disabled and sessions revoked.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
}

async function deleteUser(user) {
  if (!confirm(`Permanently delete account "${user.username}" and its grants?`)) return;
  try {
    await api(`/api/users/${user.id}`, { method: "DELETE" });
    toast("Account deleted.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
}

async function resetUserPassword(user) {
  state.resetUserId = user.id;
  $("#reset-password-title").textContent = `Reset ${user.username}'s password`;
  $("#reset-password-form").reset();
  $("#reset-password-dialog").showModal();
}

function renderGrants(grants) {
  const list = $("#grant-list");
  list.replaceChildren();
  if (!grants.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No folder grants have been created.";
    list.append(empty);
    return;
  }
  for (const grant of grants) {
    const item = document.createElement("div");
    item.className = "grant-item";
    const label = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = `${grant.username} · ${grant.path}`;
    const detail = document.createElement("small");
    detail.textContent = `${grant.permissions.length ? grant.permissions.join(", ") : "No access"} · ${grant.inherit ? "inherited" : "this folder only"}`;
    label.append(name, detail);
    const remove = document.createElement("button");
    remove.className = "text-button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => deleteGrant(grant));
    item.append(label, remove);
    list.append(item);
  }
}

async function deleteGrant(grant) {
  if (!confirm(`Remove ${grant.username}'s grant for ${grant.path}?`)) return;
  try {
    await api(`/api/grants/${grant.id}`, { method: "DELETE" });
    toast("Folder grant removed.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
}

function updateGrantScope() {
  const account = $("#grant-user").selectedOptions[0];
  $("#grant-scope").textContent = account
    ? `This rule changes only ${account.textContent}. Grants apply separately to every USER and ADMIN; Root_user is unrestricted.`
    : "Create a USER or ADMIN account before assigning folder access.";
  $("#grant-form button[type='submit']").disabled = !account;
}

function selectPermissionPreset(name) {
  const permissions = new Set(PERMISSION_PRESETS[name] || []);
  $$(".permission-options input").forEach((input) => { input.checked = permissions.has(input.value); });
  $$("[data-permission-preset]").forEach((button) => {
    button.classList.toggle("active", button.dataset.permissionPreset === name);
  });
}

$$("[data-permission-preset]").forEach((button) => button.addEventListener("click", () => {
  if (button.dataset.permissionPreset !== "custom") selectPermissionPreset(button.dataset.permissionPreset);
  else $$("[data-permission-preset]").forEach((item) => item.classList.toggle("active", item === button));
}));
$$(".permission-options input").forEach((input) => input.addEventListener("change", () => {
  $$("[data-permission-preset]").forEach((button) => {
    button.classList.toggle("active", button.dataset.permissionPreset === "custom");
  });
}));
$("#grant-user").addEventListener("change", updateGrantScope);

$("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api("/api/users", { method: "POST", body: JSON.stringify(Object.fromEntries(form.entries())) });
    event.currentTarget.reset();
    toast("Account created.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
});

$("#grant-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const permissions = $$(".permission-options input:checked").map((input) => input.value);
  try {
    await api("/api/grants", {
      method: "POST",
      body: JSON.stringify({
        user_id: Number($("#grant-user").value),
        path: $("#grant-path").value,
        permissions,
        inherit: $("#grant-inherit").checked,
      }),
    });
    toast("Folder grant saved.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
});

$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("#new-password").value;
  try {
    await api("/api/auth/password", { method: "PUT", body: JSON.stringify({ password }) });
    event.currentTarget.reset();
    showAuth();
    toast("Password changed. Sign in again.");
  } catch (error) { toast(error.message, true); }
});

$("#reset-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("#reset-password-input").value;
  try {
    await api(`/api/users/${state.resetUserId}/password`, {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    $("#reset-password-dialog").close();
    toast("Password reset; their existing sessions were revoked.");
    await loadAdmin();
  } catch (error) { toast(error.message, true); }
});

$("#reset-password-cancel").addEventListener("click", () => $("#reset-password-dialog").close());

function applyTheme(name, theme) {
  const colors = theme.colors || theme;
  const normalized = { name, version: 1, colors };
  if (!validateTheme(normalized)) {
    toast("The selected theme is invalid.", true);
    return;
  }
  state.theme = name;
  for (const [key, value] of Object.entries(colors)) {
    document.documentElement.style.setProperty(`--${key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`, value);
  }
  localStorage.setItem("scc-theme-name", name);
  localStorage.setItem("scc-theme", JSON.stringify(normalized));
  recordClientActivity("appearance_changed", name);
  renderThemes();
}

function getSavedTheme() {
  try {
    const saved = JSON.parse(localStorage.getItem("scc-theme") || "null");
    if (saved && validateTheme(saved)) return saved;
    if (saved) toast("Saved theme was invalid and has been cleared.", true);
    localStorage.removeItem("scc-theme");
    localStorage.removeItem("scc-theme-name");
    return null;
  } catch {
    localStorage.removeItem("scc-theme");
    localStorage.removeItem("scc-theme-name");
    toast("Saved theme data could not be read and has been cleared.", true);
    return null;
  }
}

function renderThemes() {
  const grid = $("#theme-grid");
  if (!grid) return;
  grid.replaceChildren();
  const saved = getSavedTheme();
  const themes = { ...THEMES, ...(saved && !THEMES[state.theme] ? { [state.theme]: saved } : {}) };
  for (const [name, colors] of Object.entries(themes)) {
    const card = document.createElement("button");
    card.className = `theme-card${name === state.theme ? " selected" : ""}`;
    const preview = document.createElement("span");
    preview.className = "theme-preview";
    const side = document.createElement("i");
    side.className = "preview-sidebar";
    side.style.background = colors.colors?.sidebar || colors.sidebar;
    const main = document.createElement("i");
    main.className = "preview-main";
    main.style.background = colors.colors?.background || colors.background;
    for (let index = 0; index < 3; index += 1) {
      const line = document.createElement("i");
      line.style.background = index === 0 ? (colors.colors?.primary || colors.primary) : (colors.colors?.surface || colors.surface);
      main.append(line);
    }
    preview.append(side, main);
    const title = document.createElement("span");
    title.className = "theme-name";
    title.textContent = name;
    card.append(preview, title);
    card.addEventListener("click", () => applyTheme(name, { colors: colors.colors || colors }));
    grid.append(card);
  }
}

function validateTheme(theme) {
  const colorKeys = ["background", "surface", "sidebar", "primary", "text", "muted", "border"];
  if (!theme || typeof theme !== "object" || typeof theme.name !== "string" || theme.name.length < 1 || theme.name.length > 40 || theme.version !== 1 || !theme.colors || typeof theme.colors !== "object") return false;
  return colorKeys.every((key) => typeof theme.colors[key] === "string" && /^#[0-9a-fA-F]{6}$/.test(theme.colors[key]));
}

$("#theme-import").addEventListener("change", async (event) => {
  const file = event.currentTarget.files[0];
  if (!file) return;
  try {
    if (file.size > 32768) throw new Error("Theme file must be 32 KB or smaller.");
    const theme = JSON.parse(await file.text());
    if (!validateTheme(theme)) throw new Error("Theme must use the supported version 1 JSON format and seven hex colors.");
    state.theme = theme.name;
    applyTheme(theme.name, theme);
    toast("Theme imported.");
  } catch (error) { toast(error.message || "Invalid theme JSON.", true); }
  event.currentTarget.value = "";
});

$("#theme-export").addEventListener("click", () => {
  const saved = getSavedTheme();
  const payload = {
    name: state.theme,
    version: 1,
    colors: saved?.colors || THEMES[state.theme] || THEMES.Midnight,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.theme.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

const savedTheme = getSavedTheme();
state.theme = savedTheme?.name || "Midnight";
if (savedTheme) applyTheme(state.theme, savedTheme);
else renderThemes();

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const setup = event.currentTarget.dataset.setup === "true";
  const username = $("#auth-username").value.trim();
  const password = $("#auth-password").value;
  try {
    const user = setup
      ? await api("/api/setup", {
          method: "POST",
          body: JSON.stringify({ setup_token: $("#setup-token").value.trim(), username, password }),
        })
      : await api("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    toast(setup ? "Root_user account created." : "Signed in.");
    showApp(user);
  } catch (error) { toast(error.message, true); }
});

$("#logout").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
    showAuth();
    toast("Signed out.");
  } catch (error) { toast(error.message, true); }
});

$$("[data-nav]").forEach((button) => button.addEventListener("click", (event) => {
  event.preventDefault();
  const view = event.currentTarget.dataset.nav;
  if (view === "access" && state.user?.role !== "owner") return;
  navigate(view);
}));

let draggedMenuKey = null;
$$(".main-nav .nav-item").forEach((item) => {
  item.addEventListener("dragstart", (event) => {
    draggedMenuKey = item.dataset.menuKey;
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", draggedMenuKey);
    item.classList.add("dragging");
  });
  item.addEventListener("dragover", (event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  });
  item.addEventListener("drop", (event) => {
    event.preventDefault();
    reorderMenuItem(draggedMenuKey || event.dataTransfer.getData("text/plain"), item.dataset.menuKey);
  });
  item.addEventListener("dragend", () => {
    draggedMenuKey = null;
    item.classList.remove("dragging");
  });
});

bootstrap();
