const $ = (id) => document.getElementById(id);
let accessToken = sessionStorage.getItem("accessToken") || "";
let currentNote = null;

function show(value) { $("result").textContent = JSON.stringify(value, null, 2); }
function setStatus(text) { $("status").textContent = text; }

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(`/api/v1${path}`, { ...options, headers });
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(payload?.error || `HTTP ${response.status}`);
  return payload;
}

async function authenticate(register = false) {
  const credentials = { login: $("login").value, password: $("password").value };
  if (register) await api("/auth/register", { method: "POST", body: JSON.stringify(credentials) });
  const session = await api("/auth/login", { method: "POST", body: JSON.stringify(credentials) });
  accessToken = session.accessToken;
  sessionStorage.setItem("accessToken", accessToken);
  setStatus(`Выполнен вход: ${credentials.login}`);
  show(session);
}

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try { await authenticate(false); } catch (error) { show({ error: error.message }); }
});

$("register").addEventListener("click", async () => {
  try { await authenticate(true); } catch (error) { show({ error: error.message }); }
});

$("note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    currentNote = await api("/notes", {
      method: "POST",
      body: JSON.stringify({ title: $("title").value, markdown: $("markdown").value, lifetimeDays: Number($("lifetime").value) })
    });
    show(currentNote);
    $("share-actions").classList.remove("hidden");
  } catch (error) { show({ error: error.message }); }
});

$("share-actions").addEventListener("click", async (event) => {
  if (!event.target.dataset.kind || !currentNote) return;
  try {
    const token = await api(`/notes/${currentNote.id}/tokens`, {
      method: "POST",
      body: JSON.stringify({ type: event.target.dataset.kind, expiresInMinutes: 60 })
    });
    const url = `${location.origin}/api/v1/notes/shared/${token.token}`;
    $("share-link").innerHTML = "";
    const link = document.createElement("a");
    link.href = url;
    link.textContent = `${token.type}: ${url}`;
    $("share-link").append(link);
  } catch (error) { show({ error: error.message }); }
});

if (accessToken) setStatus("Сессия восстановлена");
