// Nulkratos-Core — minimal service worker
// Exists only to satisfy navigator.serviceWorker.register('/sw.js')
// No caching — all message data must stay server-authoritative and encrypted.

const VERSION = 'nk-sw-v1';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Pass all fetches straight through — no cache interception.
self.addEventListener('fetch', e => e.respondWith(fetch(e.request)));
