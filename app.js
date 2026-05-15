import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getFirestore, initializeFirestore, persistentLocalCache,
  doc, getDoc, setDoc, addDoc, updateDoc, deleteDoc,
  collection, query, orderBy, onSnapshot, serverTimestamp,
  getDocs, writeBatch, enableNetwork
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';
import { getAnalytics, logEvent } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-analytics.js';

const FIREBASE_CONFIG = {
  apiKey: "AIzaSyDQttXH6DGPcG0UXAnIsgTmLzAzDHzV1T4",
  authDomain: "nulkratos-core.firebaseapp.com",
  projectId: "nulkratos-core",
  appId: "1:677574093910:web:733304939800ea172c1ff7",
  measurementId: "G-SWBWH660C5", 
};

const FS_CHANNELS = 'cd_channels';
const FS_PING_DOC = '__cd_ping__';

function isConfigPlaceholder(cfg) {
  return !cfg.apiKey || cfg.apiKey.includes('YOUR_') || !cfg.projectId || cfg.projectId.includes('YOUR_');
}
const CONFIG_VALID = !isConfigPlaceholder(FIREBASE_CONFIG);
if (!CONFIG_VALID) {
  document.getElementById('fb-config-warn').style.display = 'block';
  document.getElementById('conn-status').className = 'conn-status config-error';
  document.getElementById('conn-status-text').textContent = '⚠ Firebase config required';
}

/* ════ CRYPTO ════ */
const ARGON2_PARAMS = { time: 3, mem: 65536, hashLen: 32, parallelism: 1, type: argon2.ArgonType.Argon2id };
const CHAFF_MIN_MS = 8000, CHAFF_MAX_MS = 45000;
const PAD_BLOCK = 512;
const TS_BUCKET_MS = 5 * 60 * 1000;

function zeroBytes(arr) { if (arr) try { arr.fill(0); } catch (_) {} }
const b64 = buf => { const a = (buf instanceof Uint8Array) ? buf : new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer ?? buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
const un64 = s => new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0)));
async function sha256Hex(str) { const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)); return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join(''); }
async function sha256Bytes(ab) { const buf = await crypto.subtle.digest('SHA-256', ab); return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join(''); }
async function blindChannelId(rawId) { return sha256Hex('cd_v1_channel:' + rawId.trim().toLowerCase()); }
const makeKeySalt = id => ('cd_key_v1_' + id).slice(0, 64);
const makeVerifySalt = id => ('cd_vfy_v1_' + id).slice(0, 64);

async function deriveMainKey(pin, blindedId) {
  const r = await argon2.hash({ pass: pin, salt: makeKeySalt(blindedId), ...ARGON2_PARAMS });
  const rawBytes = new Uint8Array(r.hash);
  const hkdfBase = await crypto.subtle.importKey('raw', rawBytes, 'HKDF', false, ['deriveKey']);
  zeroBytes(rawBytes);
  // Wipe the pin string from memory by overwriting a typed copy
  try { const pinBytes = new TextEncoder().encode(pin); zeroBytes(pinBytes); } catch(_) {}
  return crypto.subtle.deriveKey({ name:'HKDF', hash:'SHA-256', salt: new TextEncoder().encode('cd_main_aes_v1'), info: new TextEncoder().encode('cd_aes256gcm_main') }, hkdfBase, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
async function deriveRatchetMaterial(pin, blindedId) {
  const r = await argon2.hash({ pass: pin, salt: ('cd_ratchet_v1_' + blindedId).slice(0, 64), ...ARGON2_PARAMS });
  const rawBytes = new Uint8Array(r.hash);
  const mat = await crypto.subtle.importKey('raw', rawBytes, 'HKDF', false, ['deriveKey']);
  zeroBytes(rawBytes);
  try { const pinBytes = new TextEncoder().encode(pin); zeroBytes(pinBytes); } catch(_) {}
  return mat;
}
async function hashPinForVerification(pin, blindedId) { const r = await argon2.hash({ pass: pin, salt: makeVerifySalt(blindedId), ...ARGON2_PARAMS }); return r.encoded; }
async function makePinFingerprint(pin, blindedId) { return sha256Hex('cd-verify-v1:' + blindedId + ':' + pin); }
async function verifyPin(pin, data, blindedId) {
  if (pin.length !== 6) return false;
  if (data.pinFingerprint) return (await makePinFingerprint(pin, blindedId)) === data.pinFingerprint;
  if (data.pinArgon2) { try { const r = await argon2.hash({ pass: pin, salt: makeVerifySalt(blindedId), ...ARGON2_PARAMS }); return r.encoded === data.pinArgon2; } catch { return false; } }
  return false;
}
async function deriveMessageSubKey(idx, blindedId) {
  if (!VAULT.ratchetMaterial) throw new Error('No ratchet material');
  const domainSalt = new TextEncoder().encode('cd_msg_ratchet_v1:' + blindedId);
  return crypto.subtle.deriveKey({ name:'HKDF', hash:'SHA-256', salt: domainSalt, info: new TextEncoder().encode(`cd_msg_${idx}_${blindedId}`) }, VAULT.ratchetMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
function padMessage(text) {
  const enc = new TextEncoder().encode(text);
  const tgt = Math.ceil((enc.length + 4) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(tgt);
  new DataView(out.buffer).setUint32(0, enc.length, true);
  out.set(enc, 4);
  out.set(crypto.getRandomValues(new Uint8Array(tgt - 4 - enc.length)), 4 + enc.length);
  return out;
}
function unpadMessage(bytes) {
  const real = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, true);
  if (real > bytes.length - 4) throw new Error('Invalid padding');
  return new TextDecoder().decode(bytes.slice(4, 4 + real));
}
function blindTs(ms) { return Math.floor(ms / TS_BUCKET_MS) * TS_BUCKET_MS + Math.floor(Math.random() * TS_BUCKET_MS); }
function decoyFields() {
  const f = {}, count = 2 + Math.floor(Math.random() * 3);
  for (let i = 0; i < count; i++) {
    const key = '_' + Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(36)).join('');
    f[key] = b64(crypto.getRandomValues(new Uint8Array(16 + Math.floor(Math.random()*48))));
  }
  return f;
}
async function encryptWithKey(plain, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = typeof plain === 'string' ? new TextEncoder().encode(plain) : plain;
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, enc);
  return { c: b64(new Uint8Array(ct)), i: b64(iv) };
}
async function decryptWithKey(c, i, key) {
  if (!c || !i) return null;
  try { return new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv: un64(i) }, key, un64(c))); } catch { return null; }
}
async function encryptSender(name, key) { return encryptWithKey(name, key); }
async function decryptSender(c, i, key) {
  if (!c || !i) return '?';
  try { return new TextDecoder().decode(await crypto.subtle.decrypt({ name:'AES-GCM', iv: un64(i) }, key, un64(c))); } catch { return '?'; }
}
async function encryptMessage(text, idx, blindedId) { return encryptWithKey(padMessage(text), await deriveMessageSubKey(idx, blindedId)); }

const _decCache = new Map();
async function decryptMessage(c, i, idx, blindedId) {
  if (!c || !i) return '🔒 [Encrypted]';
  const cacheKey = `${blindedId}:${idx}:${c.slice(0,8)}`;
  if (_decCache.has(cacheKey)) return _decCache.get(cacheKey);
  if (_decCache.size > 500) _decCache.clear();
  try {
    const key = await deriveMessageSubKey(idx, blindedId);
    const dec = await decryptWithKey(c, i, key);
    if (!dec) { _decCache.set(cacheKey, '🔒 [Cannot decrypt — wrong PIN or corrupted]'); return _decCache.get(cacheKey); }
    const txt = unpadMessage(dec);
    _decCache.set(cacheKey, txt);
    return txt;
  } catch { return '🔒 [Decryption error]'; }
}
function clearDecryptCache() { _decCache.clear(); }

/* ━━ CHAFF ━━ */
let chaffTimer = null, chaffCount = 0;
async function sendChaffMessage() {
  if (!db || !currentRoom?.blindedId || !VAULT.ratchetMaterial) return;
  try {
    const idx = 0xFFFF0000 + Math.floor(Math.random() * 0xFFFF);
    const key = await deriveMessageSubKey(idx, currentRoom.blindedId);
    const plain = b64(crypto.getRandomValues(new Uint8Array(20 + Math.floor(Math.random()*200))));
    const { c, i } = await encryptWithKey(padMessage(plain), key);
    await addDoc(collection(db, FS_CHANNELS, currentRoom.blindedId, 'messages'), {
      c, i, _chaff: true, _bt: blindTs(Date.now()), _idx: idx, ...decoyFields(), createdAt: serverTimestamp()
    });
    chaffCount++;
    const e1 = document.getElementById('pq-chaff-count'); if (e1) e1.textContent = chaffCount;
  } catch (_) {}
  scheduleNextChaff();
}
function scheduleNextChaff() { clearTimeout(chaffTimer); if (!sessionActive) return; chaffTimer = setTimeout(sendChaffMessage, CHAFF_MIN_MS + Math.random() * (CHAFF_MAX_MS - CHAFF_MIN_MS)); }
function stopChaff() { clearTimeout(chaffTimer); chaffTimer = null; }

/* ━━ URL FRAGMENT ━━ */
function parseFragment() { try { const hash = window.location.hash.slice(1); if (hash) return Object.fromEntries(new URLSearchParams(hash)); return Object.fromEntries(new URLSearchParams(window.location.search)); } catch { return {}; } }
function buildShareLink(id) { return `${location.origin}${location.pathname}#r=${encodeURIComponent(id.trim())}`; }
function copyShareLink(id) {
  if (!id?.trim()) { toast('Enter a Channel ID first.'); return; }
  const url = buildShareLink(id);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(() => toast('🔗 Share link copied!')).catch(() => {
      prompt('Copy this link to share:', url);
    });
  } else {
    prompt('Copy this link to share:', url);
  }
}

const fragParams = parseFragment();
if (fragParams.r) {
  document.getElementById('l-room').value = fragParams.r;
  document.getElementById('fragment-banner').style.display = 'flex';
  history.replaceState(null, '', location.pathname);
}
document.getElementById('fragment-banner-dismiss').addEventListener('click', () => document.getElementById('fragment-banner').style.display='none');
document.getElementById('copy-share-btn').addEventListener('click', () => copyShareLink(document.getElementById('l-room').value));

/* ━━ FAQ TOGGLE ━━ */
window.toggleFaq = function(idx) {
  const item = document.getElementById('faq-' + idx);
  const isOpen = item.classList.contains('open');
  document.querySelectorAll('.faq-item.open').forEach(el => el.classList.remove('open'));
  if (!isOpen) item.classList.add('open');
};

/* ━━ VAULT ━━ */
let VAULT = { key: null, ratchetMaterial: null };
function wipeVault() { VAULT.key = null; VAULT.ratchetMaterial = null; clearDecryptCache(); }

/* ━━ validate enter form ━━ */
function validateEnterForm() {
  const rid = document.getElementById('l-room').value.trim();
  const name = document.getElementById('l-name').value.trim();
  const pin = pinVal('.lp');
  const btn = document.getElementById('enter-btn');
  btn.disabled = !(rid && name && pin.length === 6);
}
document.getElementById('l-room').addEventListener('input', validateEnterForm);
document.getElementById('l-name').addEventListener('input', validateEnterForm);

/* ════ FIREBASE CONNECTION ════ */
let connState = 'connecting', db = null;
let pingRetryCount = 0, pingRetryTimer = null, retryCountdownInterval = null;

function setConnStatus(state, text) {
  const el = document.getElementById('conn-status'), tel = document.getElementById('conn-status-text');
  if (!el) return;
  connState = state; el.className = `conn-status ${state}`; tel.textContent = text;
  const banner = document.getElementById('fb-retry-banner');
  if (state === 'connecting' && pingRetryCount > 0) banner.classList.add('show');
  else banner.classList.remove('show');
}

function startRetryCountdown(delayMs) {
  clearInterval(retryCountdownInterval);
  const detail = document.getElementById('fb-retry-detail'), fill = document.getElementById('fb-retry-fill');
  document.getElementById('fb-retry-banner').classList.add('show');
  fill.style.transition = 'none'; fill.style.width = '0%';
  requestAnimationFrame(() => { fill.style.transition = `width ${delayMs}ms linear`; fill.style.width = '100%'; });
  const end = Date.now() + delayMs;
  retryCountdownInterval = setInterval(() => {
    const rem = Math.max(0, Math.ceil((end - Date.now()) / 1000));
    if (detail) detail.textContent = `Attempt ${pingRetryCount} · next retry in ${rem}s`;
    if (rem <= 0) clearInterval(retryCountdownInterval);
  }, 500);
}

const PING_MAX_RETRIES = 8;

async function pingFirebase() {
  if (!CONFIG_VALID || !db) return;
  try {
    await Promise.race([
      setDoc(doc(db, FS_CHANNELS, FS_PING_DOC), { _ts: new Date().toISOString(), _r: Math.random() }, { merge: true }),
      new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error('timeout'), {code:'timeout'})), 12000))
    ]);
    pingRetryCount = 0; clearTimeout(pingRetryTimer); clearInterval(retryCountdownInterval);
    document.getElementById('fb-retry-banner').classList.remove('show');
    setConnStatus('online', 'secure channel established');
  } catch (e) {
    if (e.code === 'permission-denied' || e.code === 'not-found' || e.code === 'invalid-argument') {
      pingRetryCount = 0; document.getElementById('fb-retry-banner').classList.remove('show');
      setConnStatus('online', 'secure channel established'); return;
    }
    if (!navigator.onLine) { setConnStatus('offline', 'offline — check your connection'); document.getElementById('fb-retry-banner').classList.remove('show'); return; }
    pingRetryCount++;
    if (pingRetryCount > PING_MAX_RETRIES) {
      clearTimeout(pingRetryTimer); clearInterval(retryCountdownInterval);
      document.getElementById('fb-retry-banner').classList.remove('show');
      setConnStatus('offline', '⚠ Cannot reach server — reload to retry');
      return;
    }
    if (e.code === 'timeout' || e.code === 'unavailable' || e.code === 'deadline-exceeded' || e.message === 'timeout') {
      const base = Math.min(2000 * Math.pow(2, pingRetryCount - 1), 30000);
      const delay = base + Math.random() * 1000;
      setConnStatus('connecting', `reconnecting… (attempt ${pingRetryCount}/${PING_MAX_RETRIES})`);
      clearTimeout(pingRetryTimer); startRetryCountdown(delay);
      pingRetryTimer = setTimeout(pingFirebase, delay);
    } else { setConnStatus('offline', `Firebase error: ${e.code || e.message || 'unknown'}`); }
  }
}

window.addEventListener('online', () => { if (db) { enableNetwork(db).catch(() => {}); pingFirebase(); } });
window.addEventListener('offline', () => { clearTimeout(pingRetryTimer); clearInterval(retryCountdownInterval); document.getElementById('fb-retry-banner').classList.remove('show'); setConnStatus('offline', 'offline — check your connection'); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && connState !== 'online' && CONFIG_VALID && db) pingFirebase(); });

/* ━━ ENTER ROOM ━━ */
async function attemptEnter() {
  if (!CONFIG_VALID) { document.getElementById('l-err').textContent='Configure Firebase credentials first.'; return; }
  const rid = document.getElementById('l-room').value.trim(), name = document.getElementById('l-name').value.trim(), pin = pinVal('.lp');
  const err = document.getElementById('l-err'), btn = document.getElementById('enter-btn');
  err.textContent = '';
  if (!rid) { err.textContent = 'Enter a channel ID.'; return; }
  if (rid.length > 64) { err.textContent = 'Channel ID too long (max 64 characters).'; return; }
  if (!name) { err.textContent = 'Enter your name.'; return; }
  if (pin.length !== 6) { err.textContent = 'Enter all 6 PIN digits.'; return; }
  btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Checking…`;
  const stopProg = showArgonProgress('l-argon-progress','l-argon-bar');
  try {
    const blindedId = await blindChannelId(rid);
    const snap = await getDoc(doc(db, FS_CHANNELS, blindedId));
    if (!snap.exists()) throw new Error('room-not-found');
    const data = snap.data();
    document.getElementById('l-argon-label').textContent = '🔐 Verifying PIN (Argon2id)…';
    const pinOk = await verifyPin(pin, data, blindedId);
    if (!pinOk) throw new Error('wrong-pin');
    document.getElementById('l-argon-label').textContent = '🔑 Deriving shared key (Argon2id)…';
    VAULT.key = await deriveMainKey(pin, blindedId);
    const n1 = await decryptSender(data.enc_name1_c, data.enc_name1_i, VAULT.key);
    const n2 = await decryptSender(data.enc_name2_c, data.enc_name2_i, VAULT.key);
    const nl = name.toLowerCase();
    if (nl !== n1.toLowerCase() && nl !== n2.toLowerCase()) {
      err.textContent = 'Name not found in this channel.';
      btn.disabled = false; btn.textContent = '⬡ Enter Secure Channel'; stopProg(); wipeVault();
      validateEnterForm(); return;
    }
    mySlot = nl === n1.toLowerCase() ? 1 : 2;
    document.getElementById('l-argon-label').textContent = '⚙️ Deriving ratchet material…';
    VAULT.ratchetMaterial = await deriveRatchetMaterial(pin, blindedId);
    stopProg();
    otherLastRead = data[`lastRead${mySlot === 1 ? 2 : 1}`] || null;
    currentRoom = { roomId: rid, blindedId, ...data, displayName1: n1, displayName2: n2 };
    currentUser = name;
    const storedIdx = localStorage.getItem(`cd_msgidx_${blindedId}`);
    msgSentCount = storedIdx ? parseInt(storedIdx, 10) : 0;
    if (isNaN(msgSentCount) || msgSentCount < 0) msgSentCount = 0;
    openChat();
  } catch(e) {
    stopProg();
    if (e.message === 'room-not-found') err.textContent = 'Channel not found. Check the ID.';
    else if (e.message === 'wrong-pin') err.textContent = 'Wrong PIN. Try again.';
    else if (e.code === 'unavailable' || e.code === 'deadline-exceeded' || e.message?.includes('offline')) err.textContent = 'Cannot reach server. Check connection.';
    else if (e.code === 'permission-denied') err.textContent = 'Firebase permission denied — paste the Firestore rules.';
    else err.textContent = 'Error: ' + (e.message || 'unknown');
    btn.disabled = false; btn.textContent = '⬡ Enter Secure Channel'; validateEnterForm(); wipeVault();
  }
}

/* ━━ CREATE ROOM ━━ */
async function createRoom() {
  if (!CONFIG_VALID) { document.getElementById('s-err').textContent = 'Configure Firebase credentials first.'; return; }
  const rid = document.getElementById('s-room').value.trim(), n1 = document.getElementById('s-n1').value.trim(), n2 = document.getElementById('s-n2').value.trim(), pin = pinVal('.sp');
  const err = document.getElementById('s-err'), btn = document.getElementById('s-create');
  err.textContent = '';
  if (!rid) { err.textContent = 'Choose a channel ID.'; return; }
  if (rid.length < 3) { err.textContent = 'Channel ID must be at least 3 characters.'; return; }
  if (!n1 || !n2) { err.textContent = 'Enter both names.'; return; }
  if (n1.toLowerCase() === n2.toLowerCase()) { err.textContent = 'Names must be different.'; return; }
  if (pin.length !== 6) { err.textContent = 'Enter all 6 PIN digits.'; return; }
  btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Creating…`;
  const stopProg = showArgonProgress('s-argon-progress','s-argon-bar');
  try {
    const blindedId = await blindChannelId(rid);
    const existing = await getDoc(doc(db, FS_CHANNELS, blindedId));
    if (existing.exists()) { stopProg(); err.textContent = 'Channel ID already taken.'; btn.disabled = false; btn.textContent = 'Create Secure Channel'; return; }
    document.getElementById('s-argon-label').textContent = '🔐 Deriving Argon2id key…';
    const mainKey = await deriveMainKey(pin, blindedId);
    document.getElementById('s-argon-label').textContent = '🔐 Hashing PIN for verification…';
    const [pinArgon2, pinFP] = await Promise.all([hashPinForVerification(pin, blindedId), makePinFingerprint(pin, blindedId)]);
    const [enc1, enc2] = await Promise.all([encryptSender(n1, mainKey), encryptSender(n2, mainKey)]);
    stopProg();
    // Ephemeral per-channel ID — no persistent device fingerprint stored
    const ephemeralId = 'ep_' + Array.from(crypto.getRandomValues(new Uint8Array(9))).map(b=>b.toString(16).padStart(2,'0')).join('');
    // Bucket creation time ±5 min — same blinding applied to messages
    const bucketedCreatedAt = new Date(blindTs(Date.now()));
    await setDoc(doc(db, FS_CHANNELS, blindedId), {
      pinArgon2, pinFingerprint: pinFP,
      enc_name1_c: enc1.c, enc_name1_i: enc1.i,
      enc_name2_c: enc2.c, enc_name2_i: enc2.i,
      createdBy: ephemeralId, schemaVersion: 49,
      createdAt: bucketedCreatedAt,
      online1: false, online2: false,
      lastSeen1: null, lastSeen2: null,
      lastRead1: null, lastRead2: null,
      deleteRequest: null
    });
    addMyRoom(rid); closeOverlay('ov-create'); btn.disabled = false; btn.textContent = 'Create Secure Channel';
    try { if(analytics) logEvent(analytics, 'room_created'); } catch(e) { if(location.hostname==='localhost'||location.hostname==='127.0.0.1') console.warn('[analytics]', e); }
    pinClear('.sp'); ['s-room','s-n1','s-n2'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('l-room').value = rid; document.getElementById('l-name').value = n1;
    validateEnterForm();
    toast('✅ Secure channel created! Share the PIN with your contact securely.', 4500);
  } catch(e) {
    stopProg();
    if (e.code === 'unavailable' || e.message?.includes('offline')) err.textContent = 'Cannot reach server.';
    else if (e.code === 'permission-denied') err.textContent = 'Firebase permission denied.';
    else err.textContent = 'Failed: ' + (e.message || 'unknown');
    btn.disabled = false; btn.textContent = 'Create Secure Channel';
  }
}

/* ════ PAGE INTEGRITY ════ */
let shaPanelVisible = false, pageHashComputed = '';
function showShaPanel() {
  hidePqPanel(); hideJourneyPanel();
  const p = document.getElementById('sha-panel');
  p.classList.add('show');
  p.scrollTop = 0;
  shaPanelVisible = true;
  if (!pageHashComputed) computePageHash();
}
function hideShaPanel() { document.getElementById('sha-panel').classList.remove('show'); shaPanelVisible = false; }
async function computePageHash() {
  const statusEl = document.getElementById('pi-status'), labelEl = document.getElementById('pi-label');
  const subEl = document.getElementById('pi-sub'), iconEl = document.getElementById('pi-icon');
  statusEl.className = 'page-integrity-status checking'; iconEl.textContent = '⏳';
  labelEl.textContent = 'Computing page hash…'; subEl.textContent = 'Fetching and hashing the full page source via WebCrypto.';
  document.getElementById('pi-hash-section').style.display = 'none';
  document.getElementById('pi-details-section').style.display = 'none';
  try {
    const resp = await fetch(location.href, { cache: 'no-cache' });
    const text = await resp.text();
    const bytes = new TextEncoder().encode(text);
    const hash = await sha256Bytes(bytes.buffer);
    pageHashComputed = hash;
    statusEl.className = 'page-integrity-status ok'; iconEl.textContent = '✅';
    labelEl.textContent = 'Page integrity computed';
    subEl.textContent = 'Hash covers the full HTML/JS source. Share with your contact to confirm same app.';
    document.getElementById('pi-hash-text').textContent = hash;
    const byteWrap = document.getElementById('pi-byte-wrap');
    byteWrap.innerHTML = (hash.match(/.{1,4}/g)||[]).map(s => `<span class="sha-byte">${s}</span>`).join('');
    document.getElementById('pi-hash-section').style.display = 'block';
    document.getElementById('pi-page-size').textContent = `${(bytes.length / 1024).toFixed(1)} KB`;
    document.getElementById('pi-computed-at').textContent = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    document.getElementById('pi-details-section').style.display = 'block';
    document.getElementById('pi-copy-hash').onclick = () => { navigator.clipboard.writeText(hash).then(() => toast('Page hash copied!')); };
  } catch(e) {
    statusEl.className = 'page-integrity-status warn'; iconEl.textContent = '⚠️';
    labelEl.textContent = 'Could not compute page hash'; subEl.textContent = e.message || 'Fetch failed.';
  }
}
document.getElementById('pi-recheck').addEventListener('click', () => { pageHashComputed = ''; computePageHash(); });
document.getElementById('sha-close').addEventListener('click', hideShaPanel);
document.getElementById('opt-sha').addEventListener('click', () => { showShaPanel(); closeOptsMenu(); });

/* ━━ LIVE ENCRYPTION STATE PANEL ━━ */
let pqPanelVisible = false;
function showPqPanel() {
  hideShaPanel(); hideJourneyPanel();
  const p = document.getElementById('pq-panel');
  p.classList.add('show');
  p.scrollTop = 0;
  pqPanelVisible = true;
  document.getElementById('pq-toggle-btn')?.classList.add('pq-active');
}
function hidePqPanel() { document.getElementById('pq-panel').classList.remove('show'); pqPanelVisible = false; document.getElementById('pq-toggle-btn')?.classList.remove('pq-active'); }
document.getElementById('pq-toggle-btn').addEventListener('click', () => pqPanelVisible ? hidePqPanel() : showPqPanel());
document.getElementById('pq-close').addEventListener('click', hidePqPanel);

function updateRatchetChain(currentIdx) {
  const chain = document.getElementById('pq-ratchet-chain');
  if (currentIdx === 0) {
    chain.innerHTML = '<span class="is-tiny-hint">Send a message to see ratchet progress</span>';
    return;
  }
  const maxDots = 12;
  const visible = Math.min(currentIdx + 1, maxDots);
  const start = Math.max(0, currentIdx + 1 - visible);
  let html = '';
  if (start > 0) html += '<span class="is-ratchet-ellipsis">…</span><span class="pq-ratchet-arrow">→</span>';
  for (let i = start; i <= currentIdx; i++) {
    if (i > start) html += '<span class="pq-ratchet-arrow">→</span>';
    html += `<div class="pq-ratchet-dot${i === currentIdx ? ' current' : ''}" title="step ${i}"></div>`;
  }
  chain.innerHTML = html;
}

function updatePqPanel(info) {
  if (!info) return;
  document.getElementById('pq-ratchet-idx').textContent = info.msgIndex;
  ['pq-hybrid-hash','pq-msg-key','pq-padding','pq-ts-blind','pq-decoy'].forEach(id => document.getElementById(id)?.classList.remove('pending'));
  document.getElementById('pq-hybrid-hash').textContent = info.keyHash?.slice(0,16)+'…'+info.keyHash?.slice(-6);
  document.getElementById('pq-msg-key').textContent = `idx:${info.msgIndex} → unique sub-key`;
  document.getElementById('pq-padding').textContent = `${info.realLen}B → ${info.paddedLen}B`;
  document.getElementById('pq-ts-blind').textContent = `±${TS_BUCKET_MS/60000}min bucket`;
  document.getElementById('pq-decoy').textContent = `${info.decoyCount} random fields`;
  document.getElementById('pq-ratchet-count').textContent = msgSentCount;
  updateRatchetChain(info.msgIndex);
}

/* ════ JOURNEY PANEL ════ */
const JOURNEY_STEPS = [
  { icon:'✍️', label:'Writing your message', sub:'You typed it — exists only on your device right now.' },
  { icon:'🔑', label:'Getting a unique lock', sub:'A one-time key is created just for this message — never reused.' },
  { icon:'🔐', label:'Locking the message', sub:'Your message is scrambled so only your contact can read it.' },
  { icon:'📤', label:'Sending over the internet', sub:'The locked message travels to the server — nobody can peek.' },
  { icon:'📬', label:'Delivered to your contact', sub:'Your contact\'s device received it safely.' },
  { icon:'🔓', label:'Unlocked at the other end', sub:'Only their device, with the same PIN, can unscramble it.' },
];
let journeyPanelVisible = false, journeyCurrentStep = 0;
function buildJourneyPanel() {
  const container = document.getElementById('jp-steps');
  container.innerHTML = JOURNEY_STEPS.map((s,i) => `
    <div class="jp-step pending" id="jp-step-${i}">
      <div class="jp-step-icon">${s.icon}</div>
      <div class="jp-step-text">
        <div class="jp-step-label">${s.label}</div>
        <div class="jp-step-sub">${s.sub}</div>
      </div>
      <span class="jp-step-check">✅</span>
    </div>
  `).join('');
}
function showJourneyPanel() {
  hideShaPanel(); hidePqPanel();
  const p = document.getElementById('journey-panel');
  p.classList.add('show');
  p.scrollTop = 0;
  journeyPanelVisible = true;
  document.getElementById('journey-toggle-btn').classList.add('active');
}
function hideJourneyPanel() { document.getElementById('journey-panel').classList.remove('show'); journeyPanelVisible = false; document.getElementById('journey-toggle-btn').classList.remove('active'); }
function journeySetStep(step) {
  journeyCurrentStep = step;
  const totalSteps = JOURNEY_STEPS.length;
  JOURNEY_STEPS.forEach((_, i) => {
    const el = document.getElementById(`jp-step-${i}`); if (!el) return;
    if (i < step - 1) el.className = 'jp-step done';
    else if (i === step - 1) el.className = 'jp-step active';
    else el.className = 'jp-step pending';
  });
  const pct = Math.round(((step - 1) / totalSteps) * 100);
  document.getElementById('jp-progress-fill').style.width = pct + '%';
  const pill = document.getElementById('jp-status-pill'), pillText = document.getElementById('jp-status-text');
  if (step < totalSteps) { pill.className = 'jp-status-pill'; pillText.textContent = 'In progress…'; }
  else { pill.className = 'jp-status-pill done'; pillText.textContent = 'Delivered ✓'; }
}
function journeyFinish() {
  JOURNEY_STEPS.forEach((_, i) => { const el = document.getElementById(`jp-step-${i}`); if (el) el.className = 'jp-step done'; });
  document.getElementById('jp-progress-fill').style.width = '100%';
  document.getElementById('jp-status-pill').className = 'jp-status-pill done';
  document.getElementById('jp-status-text').textContent = 'Delivered ✓';
}
function journeyReset() {
  JOURNEY_STEPS.forEach((_, i) => { const el = document.getElementById(`jp-step-${i}`); if (el) el.className = 'jp-step pending'; });
  document.getElementById('jp-progress-fill').style.width = '0%';
  document.getElementById('jp-status-pill').className = 'jp-status-pill';
  document.getElementById('jp-status-text').textContent = 'Waiting…';
  journeyCurrentStep = 0;
}
document.getElementById('journey-toggle-btn').addEventListener('click', () => journeyPanelVisible ? hideJourneyPanel() : showJourneyPanel());
document.getElementById('jp-close').addEventListener('click', hideJourneyPanel);

/* ━━ CLICK OUTSIDE TO CLOSE PANELS ━━ */
document.addEventListener('pointerdown', e => {
  const journeyPanel = document.getElementById('journey-panel');
  const pqPanel = document.getElementById('pq-panel');
  const shaPanel = document.getElementById('sha-panel');
  const journeyBtn = document.getElementById('journey-toggle-btn');
  const pqBtn = document.getElementById('pq-toggle-btn');
  const optsCryptoBtn = document.getElementById('opt-crypto-mobile');
  const optsShaBtns = [document.getElementById('opt-sha')];
  if (journeyPanelVisible && journeyPanel && !journeyPanel.contains(e.target) && !journeyBtn.contains(e.target)) {
    hideJourneyPanel();
  }
  if (pqPanelVisible && pqPanel && !pqPanel.contains(e.target) && !(pqBtn&&pqBtn.contains(e.target)) && !(optsCryptoBtn&&optsCryptoBtn.contains(e.target))) {
    hidePqPanel();
  }
  if (shaPanelVisible && shaPanel && !shaPanel.contains(e.target) && !optsShaBtns.some(b=>b&&b.contains(e.target))) {
    hideShaPanel();
  }
}, true);

/* ━━ MINI BAR ━━ */
const MJB_TEXTS = [
  { icon:'✍️', text:'Getting your message ready…' },
  { icon:'🔑', text:'Creating a unique lock for this message…' },
  { icon:'🔐', text:'Locking the message so only they can read it…' },
  { icon:'📤', text:'Sending it over the internet…' },
  { icon:'📬', text:'Delivered to your contact!' },
  { icon:'✅', text:'Message sent and secured!' },
];
let mjbStartTime = 0, mjbFadeTimer = null;
const MJB = {
  show() { clearTimeout(mjbFadeTimer); const b = document.getElementById('mini-journey-bar'); b.classList.remove('fading'); void b.offsetWidth; b.classList.add('active'); },
  hide() { const b = document.getElementById('mini-journey-bar'); b.classList.add('fading'); mjbFadeTimer = setTimeout(() => { b.classList.remove('active','fading'); this.reset(); }, 560); },
  reset() { document.getElementById('mjb-icon').textContent='🔐'; document.getElementById('mjb-friendly-text').textContent='Preparing your message…'; document.getElementById('mjb-friendly-text').className='mjb-friendly-text'; document.getElementById('mjb-time-label').textContent=''; document.getElementById('mjb-time-label').className='mjb-time-label'; document.getElementById('mjb-dots').style.display='flex'; },
  goStep(step) { const s=MJB_TEXTS[step-1]||MJB_TEXTS[0]; document.getElementById('mjb-icon').textContent=s.icon; document.getElementById('mjb-friendly-text').textContent=s.text; document.getElementById('mjb-friendly-text').className='mjb-friendly-text'+(step>=5?' done':''); const t=document.getElementById('mjb-time-label'); t.textContent=mjbStartTime?(Date.now()-mjbStartTime)+'ms':''; t.className='mjb-time-label'+(step>=5?' done':''); if(journeyPanelVisible)journeySetStep(step); },
  finish() { document.getElementById('mjb-icon').textContent='✅'; document.getElementById('mjb-friendly-text').textContent='Message sent and secured!'; document.getElementById('mjb-friendly-text').className='mjb-friendly-text done'; document.getElementById('mjb-dots').style.display='none'; const t=document.getElementById('mjb-time-label'); t.textContent=mjbStartTime?(Date.now()-mjbStartTime)+'ms':''; t.className='mjb-time-label done'; if(journeyPanelVisible)journeyFinish(); clearTimeout(mjbFadeTimer); mjbFadeTimer=setTimeout(()=>this.hide(),3500); }
};

/* ━━ SECURITY LOCK ━━ */
let securityLockActive = false, lockDebounceTimer = null;
function applySecurityLock() {
  if (!sessionActive || securityLockActive) return;
  securityLockActive = true;
  document.getElementById('security-overlay').classList.add('show');
  setTimeout(() => hardLock(), 300);
}
async function hardLock() {
  if (db && currentRoom?.blindedId && mySlot) { try { await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId), {[`online${mySlot}`]:false}); } catch(_) {} }
  if (unsubMsgs) { unsubMsgs(); unsubMsgs=null; }
  if (unsubRoom) { unsubRoom(); unsubRoom=null; }
  clearInterval(presenceTimer); clearInterval(lastSeenTimer); stopChaff();
  // ratchet index (cd_msgidx_*) intentionally kept in localStorage — not wiped on lock so re-entering user never reuses sub-key indices
  wipeVault();
  sessionActive=false; securityLockActive=false; isDeleting=false;
  currentRoom=null; currentUser=null; mySlot=null; replyToData=null; msgSentCount=0; chaffCount=0; _lastKnownThemCount=0;
  document.getElementById('security-overlay').classList.remove('show');
  document.getElementById('reply-bar').classList.remove('show');
  document.getElementById('emoji-panel').classList.remove('open');
  hidePqPanel(); hideShaPanel(); hideJourneyPanel(); MJB.hide(); MJB.reset();
  journeyReset(); pageHashComputed = '';
  hideFab();
  unreadBelowFold = 0;
  const msgsEl=document.getElementById('msgs');
  msgsEl.querySelectorAll('.msg-row,.day-pill').forEach(el=>el.remove());
  document.getElementById('empty-msgs').style.display='flex';
  pinClear('.lp'); document.getElementById('l-err').textContent='';
  const enterBtn = document.getElementById('enter-btn');
  enterBtn.textContent = '⬡ Enter Secure Channel';
  validateEnterForm();
  showScreen('lock');
}
document.addEventListener('visibilitychange', () => {
  clearTimeout(lockDebounceTimer);
  if (document.hidden && sessionActive) { lockDebounceTimer = setTimeout(() => { if (document.hidden && sessionActive) applySecurityLock(); }, 8000); }
});

/* ━━ PRESENCE ━━ */
async function presenceSet(online) {
  if (!db || !currentRoom?.blindedId || !mySlot) return;
  // Bucket lastSeen to ±5 min window — hides exact activity timing
  try { await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId), { [`online${mySlot}`]: online, [`lastSeen${mySlot}`]: new Date(blindTs(Date.now())) }); } catch(_) {}
}
async function readReceipt() {
  if (!db || !currentRoom?.blindedId || !mySlot) return;
  // Bucket lastRead to ±5 min window — hides exact read timing
  try { await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId), { [`lastRead${mySlot}`]: new Date(blindTs(Date.now())) }); } catch(_) {}
}

const TICK1=`<svg width="13" height="10" viewBox="0 0 13 10" fill="none"><path d="M1.5 5L4.5 8L11 1.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const TICK2=`<svg width="19" height="10" viewBox="0 0 19 10" fill="none"><path d="M1 5L4 8L10.5 1.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M7 5L10 8L16.5 1.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
function getTickStatus(ts) { if(!ts)return'sending'; if(otherLastRead){const m=ts.toDate?ts.toDate().getTime():ts instanceof Date?ts.getTime():0,r=otherLastRead.toDate?otherLastRead.toDate().getTime():otherLastRead instanceof Date?otherLastRead.getTime():0;if(r>=m)return'read';} return'sent'; }
function rerenderTicks() { msgCache.forEach(({id,ts})=>{const el=document.getElementById(`tk-${id}`);if(!el||!ts)return;const s=getTickStatus(ts);el.className=`ticks ${s==='read'?'blue':'gray'}`;el.innerHTML=s==='sending'?TICK1:TICK2;}); }

function startLastSeenTicker() {
  clearInterval(lastSeenTimer);
  lastSeenTimer=setInterval(()=>{
    if(!currentRoom||!mySlot)return;
    const os=mySlot===1?2:1,st=document.getElementById('c-status'),dot=document.getElementById('c-av-dot'),av=document.getElementById('c-avatar');
    if(!lastSeenTs){dot.classList.remove('on');av.classList.remove('online');st.textContent='offline';st.className='c-status';return;}
    const d=lastSeenTs.toDate?lastSeenTs.toDate():lastSeenTs instanceof Date?lastSeenTs:new Date(lastSeenTs),diff=Date.now()-d.getTime();
    if(diff<90000&&currentRoom[`online${os}`]){dot.classList.add('on');av.classList.add('online');st.textContent='online';st.className='c-status live';}
    else{dot.classList.remove('on');av.classList.remove('online');st.textContent=`last seen ${fdate2(lastSeenTs)}`;st.className='c-status';}
  },1000);
}

function startRoomListener() {
  if (unsubRoom) unsubRoom();
  unsubRoom=onSnapshot(doc(db, FS_CHANNELS, currentRoom.blindedId),snap=>{
    if(!snap.exists()){wipeVault();alert('Channel was deleted.');location.reload();return;}
    const d=snap.data();currentRoom={...currentRoom,...d};
    const os=mySlot===1?2:1;lastSeenTs=d[`lastSeen${os}`]||null;
    const nr=d[`lastRead${os}`];if(nr){otherLastRead=nr;rerenderTicks();}
    updateDeleteBanner(d);updatePresenceUI(d);
  });
}

function updatePresenceUI(d) {
  if(!mySlot)return;
  const os=mySlot===1?2:1,dot=document.getElementById('c-av-dot'),st=document.getElementById('c-status'),av=document.getElementById('c-avatar');
  const ls=d[`lastSeen${os}`];
  if(ls){const ms=ls.toDate?ls.toDate().getTime():ls instanceof Date?ls.getTime():0;if(d[`online${os}`]&&Date.now()-ms<90000){dot.classList.add('on');av.classList.add('online');st.textContent='online';st.className='c-status live';}else{dot.classList.remove('on');av.classList.remove('online');st.textContent=`last seen ${fdate2(ls)}`;st.className='c-status';}}
  else{dot.classList.remove('on');av.classList.remove('online');st.textContent='offline';st.className='c-status';}
}

/* ━━ REACTIONS ━━ */
async function setReaction(msgId, emoji) {
  if (!db || !currentRoom?.blindedId || !mySlot) return;
  try {
    const ref=doc(db, FS_CHANNELS, currentRoom.blindedId,'messages',msgId);
    const snap=await getDoc(ref);
    if (snap.exists()) { const curr=snap.data()[`reaction_${mySlot}`]||''; await updateDoc(ref, { [`reaction_${mySlot}`]: curr===emoji?'':emoji }); }
  } catch { toast('Failed.'); }
}
const getReactionDisplay = data => { const r1=data['reaction_1']||'',r2=data['reaction_2']||'',all=[r1,r2].filter(Boolean); return all.length?[...new Set(all)].join(''):'' };

/* ━━ BUBBLE INTERACTIONS ━━ */
function setupBubbleInteraction(el, msgId, msgText, isYou) {
  let lastTap=0,lpTimer=null,didLP=false,sx=0,sy=0;
  el.addEventListener('contextmenu',e=>e.preventDefault());
  function tap(e){if(didLP){didLP=false;return;}const now=Date.now(),d=now-lastTap;lastTap=now;if(d<350&&d>30){triggerHeartBurst(e);setReaction(msgId,'❤️');}}
  function startLP(e){didLP=false;sx=e.clientX|(e.touches?.[0]?.clientX??0);sy=e.clientY|(e.touches?.[0]?.clientY??0);lpTimer=setTimeout(()=>{didLP=true;showLongPressMenu(e,el,msgId,msgText,isYou);},480);}
  function cancelLP(){clearTimeout(lpTimer);}
  function checkMove(e){const cx=e.clientX|(e.touches?.[0]?.clientX??sx),cy=e.clientY|(e.touches?.[0]?.clientY??sy);if(Math.abs(cx-sx)>10||Math.abs(cy-sy)>10)cancelLP();}
  el.addEventListener('pointerdown',startLP);el.addEventListener('pointermove',checkMove);
  el.addEventListener('pointerup',e=>{cancelLP();if(!didLP)tap(e);});el.addEventListener('pointercancel',cancelLP);
}
function triggerHeartBurst(e){const h=document.createElement('div');h.className='heart-burst';h.textContent='❤️';const x=e.clientX??window.innerWidth/2,y=e.clientY??window.innerHeight/2;h.style.left=(x-16)+'px';h.style.top=(y-16)+'px';document.body.appendChild(h);setTimeout(()=>h.remove(),700);}

let menuOpen=false;
function showLongPressMenu(e, el, msgId, msgText, isYou) {
  ctxTargetId=msgId;ctxTargetText=msgText;ctxTargetIsYou=isYou;
  ctxTargetSender=isYou?currentUser:(mySlot===1?currentRoom?.displayName2:currentRoom?.displayName1)||'?';
  const rp=document.getElementById('reaction-picker'),ctx=document.getElementById('ctx-menu');
  const vw=window.innerWidth,vh=window.innerHeight,rect=el.getBoundingClientRect();
  const rpW=280,rpH=50,ctxW=185,ctxH=130;
  let rpL=Math.max(8,Math.min(rect.left+rect.width/2-rpW/2,vw-rpW-8));
  let rpT=rect.top-rpH-14;if(rpT<70)rpT=rect.bottom+12;
  let ctxL=Math.max(8,Math.min(isYou?rect.right-ctxW:rect.left,vw-ctxW-8));
  let ctxT=rpT-ctxH-8;if(ctxT<70)ctxT=rpT+rpH+8;if(ctxT+ctxH>vh-10)ctxT=vh-ctxH-10;
  rp.style.left=rpL+'px';rp.style.top=rpT+'px';ctx.style.left=ctxL+'px';ctx.style.top=ctxT+'px';
  document.getElementById('ctx-del').style.display=isYou?'flex':'none';
  rp.classList.add('open');ctx.classList.add('open');menuOpen=true;e.preventDefault?.();e.stopPropagation?.();
}
document.addEventListener('pointerdown',e=>{if(!menuOpen)return;const ctx=document.getElementById('ctx-menu'),rp=document.getElementById('reaction-picker');if(!ctx.contains(e.target)&&!rp.contains(e.target))closeAllMenus();},true);
function closeAllMenus(){document.getElementById('ctx-menu').classList.remove('open');document.getElementById('reaction-picker').classList.remove('open');menuOpen=false;}
document.getElementById('reaction-picker').addEventListener('click',e=>{const b=e.target.closest('.rp-emoji');if(!b||!ctxTargetId)return;setReaction(ctxTargetId,b.dataset.emoji);closeAllMenus();});
document.getElementById('ctx-copy').addEventListener('click',()=>{if(ctxTargetText)navigator.clipboard.writeText(ctxTargetText).then(()=>toast('Copied!'));closeAllMenus();});
document.getElementById('ctx-reply').addEventListener('click',()=>{
  if(!ctxTargetText)return;
  replyToData={sender:ctxTargetSender,text:ctxTargetText};
  document.getElementById('reply-bar-name').textContent=ctxTargetSender;
  document.getElementById('reply-bar-text').textContent=ctxTargetText.slice(0,80)+(ctxTargetText.length>80?'…':'');
  document.getElementById('reply-bar').classList.add('show');
  document.getElementById('c-input').focus();
  closeAllMenus();
});
document.getElementById('reply-bar-close').addEventListener('click',()=>{replyToData=null;document.getElementById('reply-bar').classList.remove('show');});
document.getElementById('ctx-del').addEventListener('click',async()=>{
  if(!ctxTargetId||!db||!currentRoom?.blindedId||!ctxTargetIsYou)return;
  try{await deleteDoc(doc(db, FS_CHANNELS, currentRoom.blindedId,'messages',ctxTargetId));toast('Message deleted.');}catch{toast('Failed.');}
  closeAllMenus();
});

/* ━━ EMOJI PANEL ━━ */
const EMOJIS={'Smileys':['😀','😂','🤣','😃','😅','😊','😍','🥰','😎','😏','🥺','😱','😡','😈','💀','💩'],'Hearts':['❤️','🧡','💛','💚','💙','💜','🖤','💔','💕','💞','💓','💗','💖','💘','💝','❤️‍🔥'],'Hands':['👋','✋','👌','✌️','🤞','👍','👎','✊','👏','🙌','🙏','💅'],'Symbols':['❤️','✅','❌','⚠️','🔴','🟡','🟢','🔵','💯','⛔','⬡','🔮','⚙️'],'Objects':['💎','🔮','🎯','🔑','💡','💰','📱','💻','🎁','🎉','✨','🌈','⚡','🔥','💧','🌙','⭐']};
let currentCat='Smileys';
function buildEmojiPanel(){const panel=document.getElementById('emoji-panel');panel.innerHTML=`<div class="emoji-cats">${Object.keys(EMOJIS).map(c=>`<button class="emoji-cat-btn${c===currentCat?' active':''}" data-cat="${c}">${c}</button>`).join('')}</div><div class="emoji-grid">${EMOJIS[currentCat].map(em=>`<button data-emoji="${em}">${em}</button>`).join('')}</div>`;panel.querySelectorAll('.emoji-cat-btn').forEach(b=>b.addEventListener('click',()=>{currentCat=b.dataset.cat;buildEmojiPanel();panel.classList.add('open');}));panel.querySelectorAll('.emoji-grid button').forEach(b=>b.addEventListener('click',()=>{const inp=document.getElementById('c-input'),p=inp.selectionStart??inp.value.length;inp.value=inp.value.slice(0,p)+b.dataset.emoji+inp.value.slice(p);inp.focus();autoResize(inp);document.getElementById('send-btn').disabled=!inp.value.trim();}));}
document.getElementById('emoji-toggle-btn').addEventListener('click',e=>{e.stopPropagation();const p=document.getElementById('emoji-panel');if(p.classList.contains('open')){p.classList.remove('open');return;}buildEmojiPanel();p.classList.add('open');});
document.getElementById('c-input').addEventListener('focus',()=>document.getElementById('emoji-panel').classList.remove('open'));
document.addEventListener('click',e=>{const p=document.getElementById('emoji-panel');if(!p.contains(e.target)&&e.target.id!=='emoji-toggle-btn')p.classList.remove('open');});

/* ━━ DELETE FLOW ━━ */
let isDeleting = false;
async function requestDelete(){if(!db||!currentRoom?.blindedId)return;const cur=currentRoom.deleteRequest||null,mk=`slot${mySlot}`,ok=`slot${mySlot===1?2:1}`;let v;if(!cur)v=mk;else if(cur===ok)v='both';else{toast('You already requested deletion.');return;}try{await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId),{deleteRequest:v});}catch{toast('Failed.');}}
async function cancelDeleteRequest(){if(!db||!currentRoom?.blindedId)return;try{await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId),{deleteRequest:null});}catch{toast('Failed.');}}
function updateDeleteBanner(data){
  const banner=document.getElementById('del-banner'),txt=document.getElementById('del-banner-text'),agr=document.getElementById('del-banner-agree'),can=document.getElementById('del-banner-cancel');
  const req=data.deleteRequest||null,mk=`slot${mySlot}`,ok=`slot${mySlot===1?2:1}`;
  const os=mySlot===1?2:1,on2=currentRoom?.displayName2||(os===2?'them':'?');
  if(!req){banner.style.display='none';return;}
  if(req==='both'){if(isDeleting)return;isDeleting=true;banner.style.display='none';const bid=currentRoom?.blindedId;if(bid)setTimeout(()=>nukeRoom(bid),0);return;}
  banner.style.display='flex';
  if(req===mk){txt.textContent=`You requested deletion. Waiting for ${on2}…`;agr.style.display='none';can.style.display='inline-block';}
  else if(req===ok){txt.textContent=`${on2} wants to delete this channel.`;agr.style.display='inline-block';can.style.display='none';}
}

/* ━━ SCROLL FAB ━━ */
let fabVisible = false, fabHiding = false, unreadBelowFold = 0;
function showFab() {
  const fab = document.getElementById('scroll-fab');
  if (fabVisible) return;
  fabVisible = true; fabHiding = false;
  fab.classList.remove('hiding');
  fab.classList.add('visible');
}
function hideFab() {
  const fab = document.getElementById('scroll-fab');
  if (!fabVisible && !fabHiding) return;
  fabHiding = true; fabVisible = false;
  fab.classList.remove('visible');
  fab.classList.add('hiding');
  setTimeout(() => { fab.classList.remove('hiding'); fabHiding = false; }, 230);
  unreadBelowFold = 0;
  updateFabBadge();
}
function updateFabBadge() {
  const badge = document.getElementById('scroll-fab-badge');
  if (unreadBelowFold > 0) {
    badge.textContent = unreadBelowFold > 99 ? '99+' : String(unreadBelowFold);
    badge.classList.add('show');
  } else {
    badge.classList.remove('show');
  }
}
document.getElementById('scroll-fab').addEventListener('click', () => {
  const msgs = document.getElementById('msgs');
  msgs.scrollTo({ top: msgs.scrollHeight, behavior: 'smooth' });
  unreadBelowFold = 0;
  updateFabBadge();
  hideFab();
});

function startMsgs() {
  if (unsubMsgs) unsubMsgs();
  msgCache = [];
  unreadBelowFold = 0;
  _lastKnownThemCount = 0;
  const msgsEl = document.getElementById('msgs');

  unsubMsgs = onSnapshot(
    query(collection(db, FS_CHANNELS, currentRoom.blindedId,'messages'), orderBy('createdAt','asc')),
    async snap => {
      const wasAtBot = atBottom;
      msgCache = [];
      const frag = document.createDocumentFragment();
      msgsEl.querySelectorAll('.msg-row,.day-pill').forEach(el => el.remove());
      const real = snap.docs.filter(d => !d.data()._chaff);
      document.getElementById('empty-msgs').style.display = real.length === 0 ? 'flex' : 'none';
      let lastDay = '';
      let newThemCount = 0;

      for (const msgDoc of real) {
        const data = msgDoc.data();
        let sn = '?';
        if (data.sc && data.si) sn = await decryptSender(data.sc, data.si, VAULT.key);
        const isYou = sn.toLowerCase() === currentUser.toLowerCase();
        const idx = data._idx || 0;
        const text = await decryptMessage(data.c, data.i, idx, currentRoom.blindedId);
        if (isYou) msgCache.push({ id: msgDoc.id, ts: data.createdAt });
        if (!isYou) newThemCount++;
        const status = isYou ? getTickStatus(data.createdAt) : null;
        const react = getReactionDisplay(data);

        if (data.createdAt) {
          const d = data.createdAt.toDate ? data.createdAt.toDate() : data.createdAt instanceof Date ? data.createdAt : new Date(data.createdAt);
          const k = d.toDateString();
          if (k !== lastDay) {
            lastDay = k;
            const tod=new Date().toDateString(),yes=new Date(Date.now()-86400000).toDateString();
            const lbl=k===tod?'TODAY':k===yes?'YESTERDAY':d.toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});
            const pill=document.createElement('div');pill.className='day-pill';pill.textContent=lbl;frag.appendChild(pill);
          }
        }

        const div = document.createElement('div');
        div.className = `msg-row ${isYou?'you':'them'}${react?' has-reaction':''}`;
        let qh = '';
        if (data.replyTo_text) { const rts=data.replyTo_text.slice(0,100); qh=`<div class="bubble-quote"><div class="bubble-quote-name">${escHtml(data.replyTo_sender||'?')}</div>${escHtml(rts)}${data.replyTo_text.length>100?'…':''}</div>`; }
        div.innerHTML = `<div class="bubble" id="bubble-${msgDoc.id}">${qh}<div class="bubble-text">${escHtml(text)}</div><div class="bubble-meta"><span>${ftime(data.createdAt)}</span>${isYou?`<span id="tk-${msgDoc.id}" class="ticks ${status==='read'?'blue':'gray'}">${status==='sending'?TICK1:TICK2}</span>`:''}</div>${react?`<div class="bubble-reaction" id="react-${msgDoc.id}">${react}</div>`:''}</div>`;
        frag.appendChild(div);
      }

      msgsEl.appendChild(frag);
      const allRows = msgsEl.querySelectorAll('.msg-row');
      allRows.forEach(div => {
        const bubble = div.querySelector('.bubble');
        if (!bubble) return;
        const msgId = bubble.id.replace('bubble-','');
        const isYou = div.classList.contains('you');
        const textEl = bubble.querySelector('.bubble-text');
        const text = textEl ? textEl.textContent : '';
        setupBubbleInteraction(bubble, msgId, text, isYou);
      });

      const addedThemMsgs = Math.max(0, newThemCount - _lastKnownThemCount);
      _lastKnownThemCount = newThemCount;

      if (wasAtBot) {
        msgsEl.scrollTo({ top: msgsEl.scrollHeight, behavior: 'smooth' });
        hideFab();
      } else if (addedThemMsgs > 0) {
        unreadBelowFold += addedThemMsgs;
        updateFabBadge();
        showFab();
      }

      readReceipt();
      const bar = document.getElementById('sync-bar');
      bar.textContent = '⬡ End-to-end encrypted · Messages locked on your device';
      bar.classList.add('live'); bar.classList.remove('offline');
      if (Date.now()-mjbStartTime<10000&&mjbStartTime>0) { MJB.goStep(5); setTimeout(()=>{MJB.goStep(6);setTimeout(()=>MJB.finish(),600);},700); }
    },
    () => {
      const bar = document.getElementById('sync-bar');
      bar.textContent = '⚠ Connection lost — retrying…';
      bar.classList.remove('live'); bar.classList.add('offline');
    }
  );
}

/* ━━ OPEN CHAT ━━ */
function openChat() {
  try { if(analytics) logEvent(analytics, 'channel_joined'); } catch(e) { if(location.hostname==='localhost'||location.hostname==='127.0.0.1') console.warn('[analytics]', e); }
  showScreen('chat'); sessionActive=true; securityLockActive=false; isDeleting=false;
  const os=mySlot===1?2:1, on=currentRoom[`displayName${os}`]||'Unknown';
  document.getElementById('c-name').textContent = on;
  document.getElementById('c-avatar').textContent = inits(on);
  document.getElementById('c-roomid-btn').textContent = `⬡ ${currentRoom.roomId}`;
  buildJourneyPanel();
  startMsgs(); startRoomListener(); startLastSeenTicker();
  presenceSet(true);
  presenceTimer = setInterval(() => presenceSet(true), 40000);
  scheduleNextChaff();

  const msgs = document.getElementById('msgs');
  msgs.addEventListener('scroll', () => {
    atBottom = msgs.scrollHeight - msgs.scrollTop - msgs.clientHeight < 80;
    if (atBottom) { hideFab(); }
    else if (!fabVisible) { showFab(); }
  });
}

/* ━━ SEND MESSAGE ━━ */
async function sendMsg() {
  const input=document.getElementById('c-input'), text=input.value.trim();
  if (!text || !VAULT.key || !VAULT.ratchetMaterial) return;
  if (text.length > 4000) { toast('Message too long (max 4000 characters).'); return; }
  const sendBtn=document.getElementById('send-btn');
  input.value=''; autoResize(input); sendBtn.disabled=true; burstParticles(sendBtn);

  journeyReset();
  mjbStartTime=Date.now(); MJB.reset(); MJB.show(); MJB.goStep(1);
  try {
    await new Promise(r=>setTimeout(r,60)); MJB.goStep(2);
    const msgIndex=msgSentCount;
    await new Promise(r=>setTimeout(r,60)); MJB.goStep(3);
    const realLen=new TextEncoder().encode(text).length;
    const paddedLen=Math.ceil((realLen+4)/PAD_BLOCK)*PAD_BLOCK;
    const pkg=await encryptMessage(text, msgIndex, currentRoom.blindedId);
    const sb=await encryptSender(currentUser, VAULT.key);
    const bt=blindTs(Date.now());
    const df=decoyFields();
    const kh=await sha256Hex('cd_key_display:'+msgIndex);
    updatePqPanel({ keyHash:kh, msgIndex, realLen, paddedLen, decoyCount:Object.keys(df).length });
    await new Promise(r=>setTimeout(r,80)); MJB.goStep(4);

    const msgData = {
      c: pkg.c, i: pkg.i, sc: sb.c, si: sb.i,
      _idx: msgIndex, _bt: bt, _chaff: false,
      ...df, createdAt: serverTimestamp()
    };
    if (replyToData) { msgData.replyTo_sender = replyToData.sender; msgData.replyTo_text = replyToData.text.slice(0, 200); replyToData = null; document.getElementById('reply-bar').classList.remove('show'); }
    await addDoc(collection(db, FS_CHANNELS, currentRoom.blindedId,'messages'), msgData);
    msgSentCount++;
    if (currentRoom?.blindedId) { try { localStorage.setItem(`cd_msgidx_${currentRoom.blindedId}`, String(msgSentCount)); } catch(_) {} }
    document.getElementById('pq-ratchet-count').textContent = msgSentCount;
    autoResize(input); // reset textarea height after programmatic clear
    sendBtn.disabled = !input.value.trim();
    const jBtn = document.getElementById('journey-toggle-btn');
    jBtn.classList.remove('blink-sent'); void jBtn.offsetWidth; jBtn.classList.add('blink-sent');
    setTimeout(() => jBtn.classList.remove('blink-sent'), 1900);
  } catch(e) {
    // covers both encrypt failures and addDoc failures — always restore UI
    toast('Failed to send: ' + (e.message || 'check internet'));
    input.value = text; autoResize(input); MJB.hide();
    sendBtn.disabled = false;
  }
}

/* ━━ NUKE ROOM ━━ */
async function nukeRoom(blindedId) {
  if (!blindedId) return;
  try {
    const s=await getDocs(collection(db, FS_CHANNELS, blindedId,'messages'));
    const b=writeBatch(db); s.docs.forEach(d=>b.delete(d.ref)); b.delete(doc(db, FS_CHANNELS, blindedId)); await b.commit();
    isDeleting = false; toast('Channel permanently deleted.');
    setTimeout(()=>{wipeVault();location.reload();},900);
  } catch(e) { isDeleting = false; toast('Delete failed. Try again.'); }
}

/* ━━ MY CHANNELS ━━ */
async function loadMyRooms() {
  const body=document.getElementById('myrooms-body');
  if (!db) { body.innerHTML=`<div class="is-firebase-err">Firebase not connected.</div>`; return; }
  clearInterval(presenceTimer); clearInterval(lastSeenTimer);
  const ids=getMyRooms();
  if(!ids.length){body.innerHTML=`<div class="is-no-channels"><div class="is-no-channels-icon">⬡</div><span>No channels created on this device yet.</span></div>`;return;}
  body.innerHTML=`<div class="is-channels-heading">⬡ Secure Channels</div>`;
  // Batch all blind+fetch operations in parallel for speed
  const results = await Promise.all(ids.map(async (rId, idx) => {
    try {
      const bId = await blindChannelId(rId);
      const snap = await getDoc(doc(db, FS_CHANNELS, bId));
      return { rId, bId, snap, idx, err: null };
    } catch(e) {
      return { rId, bId: null, snap: null, idx, err: e };
    }
  }));
  for (const { rId, bId, snap, idx, err } of results) {
    const card=document.createElement('div');card.className='room-card';card.style.animationDelay=`${idx*.05}s`;
    if (err) {
      card.innerHTML=`<div class="room-card-icon">⚠️</div><div class="room-card-info"><div class="rc-id is-rc-id-warn">${rId}</div><div class="rc-date is-rc-date-muted">Failed to load</div></div>`;
    } else if(snap.exists()){card.innerHTML=`<div class="room-card-icon">⬡</div><div class="room-card-info"><div class="rc-id">${escHtml(rId)}</div><div class="rc-date is-rc-date-cyan">🔑 Fully encrypted</div><div class="rc-date">${snap.data().createdAt?fdate3(snap.data().createdAt):'date unknown'}</div></div><div class="is-rc-actions"><button class="rc-del-btn" data-rid="${rId}" data-blinded="${bId}" data-rname="${escHtml(rId)}">Delete</button><button class="share-btn is-share-btn-sm" data-share-rid="${escHtml(rId)}">🔗 Share</button></div>`;}
    else{card.innerHTML=`<div class="room-card-icon">🗑</div><div class="room-card-info"><div class="rc-id is-rc-id-muted">${rId}</div><div class="rc-date is-rc-date-muted">Channel no longer exists</div></div><button class="rc-del-btn" data-rid="${rId}" data-blinded="${bId}" data-rname="${rId}">Remove</button>`;}
    body.appendChild(card);
  }
  body.querySelectorAll('[data-share-rid]').forEach(b=>b.addEventListener('click',()=>copyShareLink(b.dataset.shareRid)));
  body.querySelectorAll('.rc-del-btn').forEach(btn=>{btn.addEventListener('click',()=>{
    const rid=btn.dataset.rid,rname=btn.dataset.rname,bId=btn.dataset.blinded;
    document.getElementById('del-modal-room-name').textContent=rname;document.getElementById('del-modal-err').textContent='';document.getElementById('del-modal-confirm').disabled=false;document.getElementById('del-modal-confirm').textContent='Yes, permanently delete';
    const ov=document.getElementById('delete-overlay');ov.classList.add('open');
    const cb=document.getElementById('del-modal-confirm'),cc=document.getElementById('del-modal-cancel');
    const cleanup=()=>{ov.classList.remove('open');cb.onclick=null;cc.onclick=null;};
    cb.onclick=async()=>{cb.disabled=true;cb.innerHTML=`<span class="spinner"></span> Deleting…`;try{const s=await getDocs(collection(db, FS_CHANNELS, bId,'messages'));const b=writeBatch(db);s.docs.forEach(d=>b.delete(d.ref));b.delete(doc(db, FS_CHANNELS, bId));await b.commit();removeMyRoom(rid);toast('Channel deleted.');loadMyRooms();}catch{document.getElementById('del-modal-err').textContent='Delete failed.';cb.disabled=false;cb.textContent='Yes, permanently delete';}cleanup();};
    cc.onclick=cleanup;ov.onclick=e=>{if(e.target===ov)cleanup();};
  });});
}

/* ━━ UTILITIES ━━ */
const inits=n=>(n||'?').slice(0,2).toUpperCase();
const ftime=ts=>{if(!ts)return'';const d=ts.toDate?ts.toDate():ts instanceof Date?ts:new Date(ts);return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});};
const fdate2=ts=>{if(!ts)return'';let d;if(typeof ts.toDate==='function'){d=ts.toDate();}else if(ts instanceof Date){d=ts;}else if(typeof ts==='number'){d=new Date(ts);}else if(typeof ts==='object'&&typeof ts.seconds==='number'){d=new Date(ts.seconds*1000+Math.floor((ts.nanoseconds||0)/1e6));}else{d=new Date(ts);}if(isNaN(d.getTime()))return'';const s=Math.floor((Date.now()-d.getTime())/1000);if(s<5)return'just now';if(s<60)return`${s}s ago`;if(s<3600)return`${Math.floor(s/60)}m ago`;if(s<86400)return`${Math.floor(s/3600)}h ago`;return d.toLocaleDateString([],{month:'short',day:'numeric'});};
const fdate3=ts=>{if(!ts)return'';let d;if(typeof ts.toDate==='function'){d=ts.toDate();}else if(ts instanceof Date){d=ts;}else if(typeof ts==='number'){d=new Date(ts);}else if(typeof ts==='object'&&typeof ts.seconds==='number'){d=new Date(ts.seconds*1000+Math.floor((ts.nanoseconds||0)/1e6));}else{d=new Date(ts);}return isNaN(d.getTime())?'':d.toLocaleDateString([],{month:'short',day:'numeric',year:'numeric'});};
const escHtml=t=>String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
function showScreen(id){document.querySelectorAll('.screen').forEach(s=>s.classList.remove('active'));document.getElementById(id).classList.add('active');}
const _toastQueue = [];
let _toastActive = false;
function toast(msg, d=2400) {
  _toastQueue.push({ msg, d });
  if (!_toastActive) _processToastQueue();
}
function _processToastQueue() {
  if (!_toastQueue.length) { _toastActive = false; return; }
  _toastActive = true;
  const { msg, d } = _toastQueue.shift();
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => {
    el.classList.remove('show');
    setTimeout(_processToastQueue, 200);
  }, d);
}
function openOverlay(id){document.getElementById(id).classList.add('open');}
function closeOverlay(id){document.getElementById(id).classList.remove('open');}
function autoResize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,110)+'px';}
function burstParticles(btn){const rect=btn.getBoundingClientRect(),cx=rect.left+rect.width/2,cy=rect.top+rect.height/2;const cs=['#00f5ff','#00c8d4','#7fffff','#00ff87','#e31aff'];for(let i=0;i<12;i++){const p=document.createElement('div');p.className='send-particle';const a=(Math.PI*2/12)*i,dist=30+Math.random()*50;p.style.cssText=`left:${cx-2.5}px;top:${cy-2.5}px;background:${cs[i%cs.length]};--tx:${Math.cos(a)*dist}px;--ty:${Math.sin(a)*dist}px;animation-duration:${.4+Math.random()*.3}s`;document.body.appendChild(p);setTimeout(()=>p.remove(),800);}}

/* ━━ OPTIONS MENU ━━ */
function positionOptsMenu() {
  const btn = document.getElementById('opts-btn'), menu = document.getElementById('opts-menu');
  const rect = btn.getBoundingClientRect();
  const vw = window.innerWidth, vh = window.innerHeight;
  const GAP = 6, EDGE = 8;
  // Clamp menu width so it never overflows viewport on small screens
  const maxW = Math.min(240, vw - EDGE * 2);
  menu.style.maxWidth = maxW + 'px';
  menu.style.visibility = 'hidden'; menu.style.display = 'block';
  const menuW = Math.min(menu.offsetWidth || 210, maxW);
  const menuH = menu.offsetHeight || 220;
  menu.style.visibility = ''; menu.style.display = '';
  // Right-align under the button, clamp to viewport edges
  let left = rect.right - menuW;
  if (left < EDGE) left = EDGE;
  if (left + menuW > vw - EDGE) left = vw - menuW - EDGE;
  // Below button preferred, flip above if it would overflow bottom
  let top = rect.bottom + GAP;
  if (top + menuH > vh - EDGE) top = rect.top - menuH - GAP;
  if (top < EDGE) top = EDGE;
  menu.style.left = left + 'px';
  menu.style.top = top + 'px';
  menu.style.right = 'auto';
  menu.style.bottom = 'auto';
}
let optsOpen = false;
function openOptsMenu() { optsOpen=true; document.getElementById('opts-btn').classList.add('open-state'); positionOptsMenu(); document.getElementById('opts-menu').classList.add('open'); }
function closeOptsMenu() { optsOpen=false; document.getElementById('opts-btn').classList.remove('open-state'); document.getElementById('opts-menu').classList.remove('open'); }
document.getElementById('opts-btn').addEventListener('click', e => { e.stopPropagation(); optsOpen ? closeOptsMenu() : openOptsMenu(); });
document.addEventListener('click', e => { if (optsOpen && !document.getElementById('opts-menu').contains(e.target) && e.target.id !== 'opts-btn') closeOptsMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeOptsMenu(); hidePqPanel(); hideShaPanel(); hideJourneyPanel(); } });
window.addEventListener('resize', () => { if (optsOpen) positionOptsMenu(); });

/* ━━ PIN HELPERS ━━ */
window.togglePin=function(sel){const ins=document.querySelectorAll(sel);const show=ins[0].type==='password';ins.forEach(i=>i.type=show?'text':'password');};
const pinVal=sel=>[...document.querySelectorAll(sel)].map(x=>x.value).join('');
const pinClear=sel=>document.querySelectorAll(sel).forEach(x=>{x.value='';x.type='password';x.classList.remove('filled');});
function setupPin(sel,onDone){
  const inputs=[...document.querySelectorAll(sel)];
  inputs.forEach((inp,i)=>{
    inp.addEventListener('keydown',e=>{if(e.key==='Backspace'){e.preventDefault();if(inp.value){inp.value='';inp.classList.remove('filled');}else if(i>0){inputs[i-1].value='';inputs[i-1].classList.remove('filled');inputs[i-1].focus();}if(sel==='.lp')validateEnterForm();return;}if(e.key==='Enter'){e.preventDefault();if(onDone)onDone();return;}if(!/^\d$/.test(e.key)&&!['Tab','Delete','ArrowLeft','ArrowRight'].includes(e.key))e.preventDefault();});
    inp.addEventListener('input',()=>{inp.value=inp.value.replace(/\D/g,'').slice(-1);if(inp.value){inp.classList.add('filled');if(i<inputs.length-1)inputs[i+1].focus();}else inp.classList.remove('filled');if(sel==='.lp')validateEnterForm();if(i===inputs.length-1&&inp.value&&onDone)setTimeout(()=>onDone(),80);});
    inp.addEventListener('paste',e=>{e.preventDefault();const v=(e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'');[...v].slice(0,inputs.length-i).forEach((ch,j)=>{if(inputs[i+j]){inputs[i+j].value=ch;inputs[i+j].classList.add('filled');}});const nx=Math.min(i+v.length,inputs.length-1);inputs[nx].focus();if([...inputs].every(x=>x.value)){if(sel==='.lp')validateEnterForm();setTimeout(()=>onDone&&onDone(),80);}});
    inp.addEventListener('click',()=>inp.select());
  });
}
function showArgonProgress(wId,bId){const wrap=document.getElementById(wId),bar=document.getElementById(bId);if(!wrap)return()=>{};wrap.classList.add('show');bar.style.width='0%';let p=0;const iv=setInterval(()=>{p+=Math.random()*6;if(p>85)p=85;bar.style.width=p+'%';},150);return()=>{clearInterval(iv);bar.style.width='100%';setTimeout(()=>wrap.classList.remove('show'),600);};}

/* ━━ SESSION STATE ━━ */
let currentUser, currentRoom, mySlot, otherLastRead;
let unsubMsgs=null, unsubRoom=null, presenceTimer=null, lastSeenTimer=null;
let atBottom=true, msgCache=[];
let sessionActive=false;
let ctxTargetId=null, ctxTargetText='', ctxTargetSender='', ctxTargetIsYou=false;
let replyToData=null, msgSentCount=0;
let lastSeenTs=null;
let _lastKnownThemCount = 0;

/* ━━ LOCAL STORAGE ━━ */
function getDeviceId(){let id=localStorage.getItem('cd_device_id');if(!id){id='nk_'+Date.now().toString(36)+'_'+Math.random().toString(36).slice(2,9);localStorage.setItem('cd_device_id',id);}return id;}
function getMyRooms(){try{return JSON.parse(localStorage.getItem('cd_my_rooms')||'[]');}catch{return[];}}
function addMyRoom(id){const r=getMyRooms();if(!r.includes(id)){r.push(id);localStorage.setItem('cd_my_rooms',JSON.stringify(r));}}
function removeMyRoom(id){localStorage.setItem('cd_my_rooms',JSON.stringify(getMyRooms().filter(r=>r!==id)));}

/* ━━ EVENT LISTENERS ━━ */
document.getElementById('enter-btn').addEventListener('click', attemptEnter);
document.getElementById('l-room').addEventListener('keydown', e=>{if(e.key==='Enter')document.getElementById('l-name').focus();});
document.getElementById('l-name').addEventListener('keydown', e=>{if(e.key==='Enter')document.querySelector('.lp').focus();});
document.getElementById('new-room-btn').addEventListener('click', ()=>openOverlay('ov-create'));
document.getElementById('s-cancel').addEventListener('click', ()=>closeOverlay('ov-create'));
document.getElementById('s-create').addEventListener('click', createRoom);
document.getElementById('myrooms-link-btn').addEventListener('click', ()=>{showScreen('myrooms');loadMyRooms();});
document.getElementById('myrooms-back').addEventListener('click', ()=>showScreen('lock'));
document.getElementById('myrooms-refresh').addEventListener('click', loadMyRooms);

document.getElementById('c-share-btn')?.addEventListener('click', ()=>{if(currentRoom)copyShareLink(currentRoom.roomId);});
document.getElementById('lock-btn')?.addEventListener('click', async()=>{
  sessionActive=false;
  if(unsubMsgs)unsubMsgs();if(unsubRoom)unsubRoom();
  clearInterval(presenceTimer);clearInterval(lastSeenTimer);stopChaff();
  if(db&&currentRoom?.blindedId&&mySlot){try{await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId),{[`online${mySlot}`]:false});}catch(_){}}
  hardLock();
});
document.getElementById('c-roomid-btn')?.addEventListener('click', ()=>{if(currentRoom)navigator.clipboard.writeText(currentRoom.roomId).then(()=>toast('Channel ID copied!'));});
document.getElementById('opt-roomid-mobile').addEventListener('click',()=>{if(currentRoom)navigator.clipboard.writeText(currentRoom.roomId).then(()=>toast('Channel ID copied!'));closeOptsMenu();});
document.getElementById('opt-share-mobile').addEventListener('click',()=>{if(currentRoom)copyShareLink(currentRoom.roomId);closeOptsMenu();});
document.getElementById('opt-crypto-mobile').addEventListener('click',()=>{showPqPanel();closeOptsMenu();});
document.getElementById('opt-lock-mobile').addEventListener('click',async()=>{
  closeOptsMenu();sessionActive=false;
  if(unsubMsgs)unsubMsgs();if(unsubRoom)unsubRoom();
  clearInterval(presenceTimer);clearInterval(lastSeenTimer);stopChaff();
  if(db&&currentRoom?.blindedId&&mySlot){try{await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId),{[`online${mySlot}`]:false});}catch(_){}}
  hardLock();
});
document.getElementById('opt-share-link').addEventListener('click', ()=>{if(currentRoom)copyShareLink(currentRoom.roomId);closeOptsMenu();});
document.getElementById('opt-del').addEventListener('click', ()=>{requestDelete();closeOptsMenu();});
document.getElementById('del-banner-agree').addEventListener('click', async()=>{try{await updateDoc(doc(db, FS_CHANNELS, currentRoom.blindedId),{deleteRequest:'both'});}catch{toast('Failed.');}});
document.getElementById('del-banner-cancel').addEventListener('click', cancelDeleteRequest);

const cinput=document.getElementById('c-input');
cinput.addEventListener('input',function(){autoResize(this);document.getElementById('send-btn').disabled=!this.value.trim();});
cinput.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();}});
document.getElementById('send-btn').addEventListener('click', sendMsg);

document.querySelectorAll('.overlay').forEach(ov=>ov.addEventListener('click',e=>{if(e.target===ov)ov.classList.remove('open');}));
setupPin('.lp', attemptEnter);
setupPin('.sp');

/* ════ FIREBASE BOOT ════ */
let analytics = null;
if (CONFIG_VALID) {
  try {
    const app = initializeApp(FIREBASE_CONFIG);
    try { analytics = getAnalytics(app); } catch(_) {}
    try { db = initializeFirestore(app, { cache: persistentLocalCache() }); } catch (_e1) { db = getFirestore(app); }
    showScreen('lock');
    setConnStatus('connecting', 'establishing secure channel…');
    setTimeout(pingFirebase, 900);
    setInterval(() => { if (!document.hidden && connState !== 'online' && navigator.onLine && CONFIG_VALID && db) pingFirebase(); }, 30000);
  } catch (e) {
    console.error('[Nulkratos-Core v4.9.6] Firebase init failed:', e);
    setConnStatus('offline', `Init failed: ${e.message}`);
    showScreen('lock');
  }
} else {
  showScreen('lock');
}
