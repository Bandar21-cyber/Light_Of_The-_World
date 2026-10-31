// Netlify Function: admin accounts, admin login and automatic sign-up retrieval for the volunteer roster.
//
//   POST   /api/login     { email, password }                  -> { token, email }   (token valid 12 hours)
//   GET    /api/signups   (admin)                              -> { submissions: [{ id, created_at, data }] }
//   GET    /api/admins    (admin)                              -> { admins: [{ email, builtIn, addedBy, addedAt }], me }
//   POST   /api/admins    (admin) { email, password }          -> add an admin
//   DELETE /api/admins?email=...  (admin)                      -> remove an admin added in the app
//   POST   /api/password  (admin) { currentPassword, newPassword } -> change your own password
//   GET    /api/roster    (admin)                              -> { data, etag }   the shared roster (null before first save)
//   PUT    /api/roster    (admin) { data, etag }               -> { etag }         save; 409 { data, etag } if someone saved first
//
// "(admin)" = send header  Authorization: Bearer <token from /api/login>
//
// Requires one environment variable in Netlify (Project configuration > Environment variables):
//   NETLIFY_API_TOKEN  = a Netlify personal access token. Used server-side only, to read this site's
//   form submissions and to sign login tokens.
// Admin accounts added in the app are stored in Netlify Blobs (store "roster-admins"); no setup needed.

import crypto from "node:crypto";

const FORM_NAME = "volunteer-signup";
const PBKDF2_ITERATIONS = 310000;
const TOKEN_HOURS = 12;
const MIN_PASSWORD = 8;
const STORE_NAME = "roster-admins";
const STORE_KEY = "accounts";

// Built-in admins (also listed in CONFIG.admins in index.html as an offline fallback).
// They can't be removed in the app, but they can change their own password there.
const BUILT_IN_ADMINS = [
  { email: "badams@uvu.edu",            salt: "eccc1c7b5139b656ddda54f9a7acf6f4", hash: "23ba8183f83e9a6764b867ff5dd2e0dbea2083c8fadbc8118f97035c3d1828dd" },
  { email: "r.huntsmanb@gmail.com",     salt: "9b5c25e578ad5309bbdd7253164e4981", hash: "703e839c8130ce6a5922034f8a448fbecc8e5b7f06053ef62aac7fae9a10b78c" },
  { email: "spencer.thunell@gmail.com", salt: "a63345dc53ab32b4011cb049a23792ac", hash: "b27f81860cc588d26341bed86f206739c47de22d4dde1da4f4c4041ec4a87bf9" }
];

export const config = { path: ["/api/login", "/api/signups", "/api/admins", "/api/password", "/api/roster", "/api/health"] };
const CODE_VERSION = "2026-10-31";
const ROSTER_STORE = "roster-data";
const ROSTER_KEY = "roster";
const MAX_ROSTER_BYTES = 4 * 1024 * 1024;

/* ---------- helpers ---------- */
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
// Tolerate common paste mistakes: spaces or line breaks, surrounding quotes, or a leading "Bearer ".
const apiToken = () => String(process.env.NETLIFY_API_TOKEN || (globalThis.Netlify?.env?.get?.("NETLIFY_API_TOKEN")) || "")
  .trim().replace(/^["']|["']$/g, "").replace(/^Bearer\s+/i, "").replace(/\s+/g, "");
const normEmail = e => String(e || "").trim().toLowerCase();
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;
const isBuiltIn = e => BUILT_IN_ADMINS.some(a => a.email === e);

function hashPassword(email, password, saltHex){
  return crypto.pbkdf2Sync(`${email}:${password}`, Buffer.from(saltHex, "hex"), PBKDF2_ITERATIONS, 32, "sha256").toString("hex");
}
function makeCredential(email, password){
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: hashPassword(email, password, salt) };
}
function sameHex(a, b){
  const x = Buffer.from(a, "hex"), y = Buffer.from(b, "hex");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
async function readBody(req){ try { return await req.json(); } catch { return {}; } }

/* ---------- admin account store (Netlify Blobs) ---------- */
// Stored shape: { accounts: { "<email>": { salt, hash, addedBy?, addedAt?, changedAt? } } }
// An entry for a built-in email is a password change; any other entry is an admin added in the app.
async function store(name = STORE_NAME){
  const t = globalThis.__ROSTER_TEST_STORE__;
  if (t) return typeof t === "function" ? t(name) : t;
  const { getStore } = await import("@netlify/blobs");
  return getStore({ name, consistency: "strong" });
}
async function loadAccounts(){
  const s = await store();
  const res = await s.getWithMetadata(STORE_KEY, { type: "json" });
  return { data: res?.data?.accounts ? res.data : { accounts: {} }, etag: res?.etag || null };
}
// Read-modify-write with optimistic locking so two admins saving at once can't overwrite each other.
async function updateAccounts(change){
  const s = await store();
  for (let attempt = 0; attempt < 5; attempt++){
    const { data, etag } = await loadAccounts();
    const result = change(data.accounts);
    if (result?.error) return result;
    const opts = etag ? { onlyIfMatch: etag } : { onlyIfNew: true };
    const { modified } = await s.setJSON(STORE_KEY, data, opts);
    if (modified !== false) return result || {};
  }
  return { error: "Someone else is saving admin changes right now. Try again.", status: 409 };
}
async function currentAdmins(){
  const { data } = await loadAccounts();
  const list = new Map(BUILT_IN_ADMINS.map(a => [a.email, { email: a.email, salt: a.salt, hash: a.hash, builtIn: true }]));
  for (const [email, acct] of Object.entries(data.accounts)){
    const prior = list.get(email);
    list.set(email, { ...(prior || {}), ...acct, email, builtIn: !!prior });
  }
  return list;
}

/* ---------- login tokens ---------- */
function signToken(email){
  const body = Buffer.from(JSON.stringify({ email, exp: Date.now() + TOKEN_HOURS * 3600e3 })).toString("base64url");
  const mac = crypto.createHmac("sha256", apiToken()).update("roster-login:" + body).digest("base64url");
  return `${body}.${mac}`;
}
async function verifyToken(req){
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expected = crypto.createHmac("sha256", apiToken()).update("roster-login:" + body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let claims;
  try { claims = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return null; }
  if (!claims.exp || claims.exp < Date.now()) return null;
  return (await currentAdmins()).has(claims.email) ? claims.email : null;   // removed admins lose access immediately
}

/* ---------- routes ---------- */
async function login(req){
  if (req.method !== "POST") return json({ error: "Use POST" }, 405);
  const { email: rawEmail, password = "" } = await readBody(req);
  const email = normEmail(rawEmail);
  const admin = (await currentAdmins()).get(email);
  // Always hash, even for unknown emails, so response time doesn't reveal which emails are admins
  const hash = hashPassword(email, String(password), (admin || BUILT_IN_ADMINS[0]).salt);
  if (!admin || !sameHex(hash, admin.hash)){
    await new Promise(r => setTimeout(r, 800));
    return json({ error: "Incorrect email or password." }, 401);
  }
  return json({ token: signToken(email), email });
}

async function signups(req, context){
  const siteId = context?.site?.id || process.env.SITE_ID;
  if (!siteId) return json({ error: "Couldn't determine this site's ID." }, 500);
  const api = async path => {
    const r = await fetch(`https://api.netlify.com/api/v1${path}`, { headers: { Authorization: `Bearer ${apiToken()}` } });
    if (!r.ok) throw Object.assign(new Error(`Netlify API ${r.status}`), { status: r.status });
    return r.json();
  };
  const forms = await api(`/sites/${siteId}/forms`);
  const form = forms.find(f => f.name === FORM_NAME);
  if (!form) return json({ submissions: [], note: `No "${FORM_NAME}" form found yet. Turn on form detection and redeploy.` });
  const submissions = [];
  for (let page = 1; page <= 50; page++){
    const batch = await api(`/forms/${form.id}/submissions?per_page=100&page=${page}`);
    for (const s of batch) submissions.push({ id: s.id, created_at: s.created_at, data: s.data || {} });
    if (batch.length < 100) break;
  }
  return json({ submissions });
}

async function admins(req, me){
  if (req.method === "GET"){
    const list = [...(await currentAdmins()).values()]
      .map(a => ({ email: a.email, builtIn: a.builtIn, addedBy: a.addedBy || null, addedAt: a.addedAt || null }))
      .sort((a, b) => (b.builtIn - a.builtIn) || a.email.localeCompare(b.email));
    return json({ admins: list, me });
  }
  if (req.method === "POST"){
    const { email: rawEmail, password = "" } = await readBody(req);
    const email = normEmail(rawEmail);
    if (!validEmail(email)) return json({ error: "Enter a valid email address." }, 400);
    if (String(password).length < MIN_PASSWORD) return json({ error: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
    if (isBuiltIn(email)) return json({ error: `${email} is already an admin.` }, 409);
    const cred = makeCredential(email, String(password));
    const res = await updateAccounts(accounts => {
      if (accounts[email]) return { error: `${email} is already an admin.`, status: 409 };
      accounts[email] = { ...cred, addedBy: me, addedAt: new Date().toISOString() };
    });
    if (res.error) return json({ error: res.error }, res.status || 400);
    return json({ ok: true, email }, 201);
  }
  if (req.method === "DELETE"){
    const email = normEmail(new URL(req.url).searchParams.get("email"));
    if (email === me) return json({ error: "You can't remove your own account." }, 400);
    if (isBuiltIn(email)) return json({ error: "Built-in admins can't be removed here." }, 400);
    const res = await updateAccounts(accounts => {
      if (!accounts[email]) return { error: "That admin wasn't found.", status: 404 };
      delete accounts[email];
    });
    if (res.error) return json({ error: res.error }, res.status || 400);
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}

/* ---------- shared roster (volunteers, assignments, shift sizes) ---------- */
async function roster(req, me){
  const s = await store(ROSTER_STORE);
  const current = async () => {
    const res = await s.getWithMetadata(ROSTER_KEY, { type: "json" });
    return { data: res?.data ?? null, etag: res?.etag || null };
  };
  if (req.method === "GET") return json(await current());
  if (req.method !== "PUT") return json({ error: "Method not allowed" }, 405);
  const raw = await req.text();
  if (raw.length > MAX_ROSTER_BYTES) return json({ error: "The roster is too large to save." }, 413);
  let body; try { body = JSON.parse(raw); } catch { return json({ error: "Invalid roster data." }, 400); }
  const data = body?.data;
  if (!data || !Array.isArray(data.volunteers) || !Array.isArray(data.assignments)) return json({ error: "Invalid roster data." }, 400);
  data.savedBy = me; data.savedAt = new Date().toISOString();
  const opts = body.etag ? { onlyIfMatch: body.etag } : { onlyIfNew: true };
  const result = await s.setJSON(ROSTER_KEY, data, opts);
  if (result?.modified === false) return json({ error: "Someone else saved first.", ...(await current()) }, 409);
  return json({ etag: result?.etag || (await current()).etag });
}

async function changePassword(req, me){
  if (req.method !== "POST") return json({ error: "Use POST" }, 405);
  const { currentPassword = "", newPassword = "" } = await readBody(req);
  const admin = (await currentAdmins()).get(me);
  if (!admin || !sameHex(hashPassword(me, String(currentPassword), admin.salt), admin.hash))
    return json({ error: "Your current password is incorrect." }, 400);
  if (String(newPassword).length < MIN_PASSWORD) return json({ error: `New password must be at least ${MIN_PASSWORD} characters.` }, 400);
  const cred = makeCredential(me, String(newPassword));
  const res = await updateAccounts(accounts => {
    accounts[me] = { ...(accounts[me] || {}), ...cred, changedAt: new Date().toISOString() };
  });
  if (res.error) return json({ error: res.error }, res.status || 400);
  return json({ ok: true });
}

/* ---------- server check: open /api/health in a browser ---------- */
async function health(context){
  const checks = [];
  const add = (name, ok, detail) => checks.push({ check: name, ok, detail });
  add("Server code", true, `Version ${CODE_VERSION} is deployed.`);
  const token = apiToken();
  add("Access token set", !!token, token ? "NETLIFY_API_TOKEN is set." : "NETLIFY_API_TOKEN is missing. Add it under Project configuration > Environment variables (Functions scope), then trigger a deploy.");
  const siteId = context?.site?.id || process.env.SITE_ID;
  if (token && siteId){
    try {
      const r = await fetch(`https://api.netlify.com/api/v1/sites/${siteId}/forms`, { headers: { Authorization: `Bearer ${token}` } });
      if (r.ok){
        const forms = await r.json();
        add("Access token works", true, "Netlify accepted the token.");
        const f = forms.find(x => x.name === FORM_NAME);
        add("Sign-up form found", !!f, f ? `"${FORM_NAME}" has ${f.submission_count ?? "?"} sign-ups.` : "No volunteer-signup form yet. Enable form detection (Project configuration > Forms), deploy, and submit a test sign-up.");
      } else add("Access token works", false, r.status === 401
        ? "Netlify rejected the token (invalid, expired or revoked). Create a new token, replace NETLIFY_API_TOKEN, then trigger a deploy."
        : `Netlify answered ${r.status}: the token can't see this site. Create it while logged in to the account that owns this site.`);
    } catch (e){ add("Access token works", false, "Couldn't reach the Netlify API: " + e.message); }
  }
  try {
    const s = await store(ROSTER_STORE);
    const res = await s.getWithMetadata(ROSTER_KEY, { type: "json" });
    await s.setJSON("health-check", { at: new Date().toISOString() });
    add("Shared storage", true, "Netlify Blobs can be read and written.");
    add("Shared roster saved", !!res?.data, res?.data
      ? `${res.data.volunteers?.length ?? 0} volunteers and ${res.data.assignments?.length ?? 0} assignments, last saved ${res.data.savedAt || "?"} by ${res.data.savedBy || "?"}.`
      : "Nothing saved yet. Log in at /admin with the new index.html deployed; the first save creates it.");
  } catch (e){
    add("Shared storage", false, "Netlify Blobs isn't working: " + e.message + ". Make sure package.json and netlify.toml are at the top of the GitHub repository, then check the latest deploy log.");
  }
  const allOk = checks.every(c => c.ok);
  return json({ summary: allOk ? "Everything is working." : "Something needs fixing: see the first check marked ok: false.", checks });
}

export default async (req, context) => {
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  if (path.endsWith("/health")) return await health(context);
  if (!apiToken()) return json({ error: "NETLIFY_API_TOKEN isn't set in this site's environment variables." }, 503);
  try {
    if (path.endsWith("/login")) return await login(req);
    const me = await verifyToken(req);
    if (!me) return json({ error: "Not logged in or session expired." }, 401);
    if (path.endsWith("/signups")) return await signups(req, context);
    if (path.endsWith("/admins")) return await admins(req, me);
    if (path.endsWith("/password")) return await changePassword(req, me);
    if (path.endsWith("/roster")) return await roster(req, me);
    return json({ error: "Not found" }, 404);
  } catch (err){
    console.error(err);
    if (err.status === 401) return json({ error: "Netlify rejected the access token: it's invalid, expired or was revoked. Create a new token and replace NETLIFY_API_TOKEN, then redeploy.", code: "token_invalid" }, 502);
    if (err.status === 403 || err.status === 404) return json({ error: "The access token works but can't see this site. Create the token while logged in to the Netlify account that owns this site, then replace NETLIFY_API_TOKEN and redeploy.", code: "token_no_access" }, 502);
    return json({ error: "Something went wrong on the server. Try again shortly." }, 500);
  }
};
