// 앱 화면(껍데기)만 저장해 두고, 목록(catalog.enc)은 항상 새로 받음.
// 녹음은 여기서 저장하지 않음(앱이 storytime-audio-* 에 최근 40개만 직접 저장 — 업데이트 때 지우지 않음).
const CACHE = 'storytime-v34';
const SHELL = ['./', 'index.html', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))); self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE && !k.startsWith('storytime-audio')).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET') return;
  if (u.pathname.includes('/st/')) { e.respondWith(stream(e.request, u)); return; }
  // 네트워크 우선, 안 되면 저장본
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok && !u.pathname.endsWith('catalog.enc') && !u.pathname.includes('/audio/')) { const c = r.clone(); caches.open(CACHE).then(x => x.put(e.request, c)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true })));
});

// ───── 바로 재생(스트리밍) ─────
// 녹음은 R2 에 64KB 조각마다 따로 잠겨 있음(머리 28바이트 'STC1'·조각크기·전체길이·기본 iv).
// <audio src="st/<id>.m4a?v=.."> 요청(Range)을 받아, 필요한 조각만 R2 에서 받아 푼 뒤 바로 흘려 보냄.
// 열쇠는 앱이 postMessage 로 넘겨 줌(서비스워커가 다시 시작돼 열쇠가 없으면 503 → 앱이 예전 방식으로 받음).
let SKEY = null, SR2 = null;
const HDR = new Map();
self.addEventListener('message', e => {
  const d = e.data || {};
  if (d.type !== 'skey') return;
  crypto.subtle.importKey('raw', d.key, 'AES-GCM', false, ['decrypt']).then(k => {
    SKEY = k; SR2 = d.r2; if (e.ports && e.ports[0]) e.ports[0].postMessage('ok');
  });
});
const join = (a, b) => { const n = new Uint8Array(a.length + b.length); n.set(a); n.set(b, a.length); return n; };
async function readHead(src) {
  if (HDR.has(src)) return HDR.get(src);
  const r = await fetch(src, { headers: { Range: 'bytes=0-27' } });
  if (!r.ok) throw new Error('head ' + r.status);
  const rd = r.body.getReader(); let b = new Uint8Array(0);
  while (b.length < 28) { const { done, value } = await rd.read(); if (done) break; b = join(b, value); }
  rd.cancel().catch(() => {});
  if (b.length < 28 || String.fromCharCode(b[0], b[1], b[2], b[3]) !== 'STC1') throw new Error('fmt');
  const dv = new DataView(b.buffer, b.byteOffset, 28);
  const h = { cs: dv.getUint32(4), n: Number(dv.getBigUint64(8)), iv: b.slice(16, 28) };
  HDR.set(src, h);
  return h;
}
async function stream(req, u) {
  try {
    if (!SKEY || !SR2) return new Response('nokey', { status: 503 });
    const id = u.pathname.split('/st/')[1].replace(/\.m4a$/, '');
    if (!/^[0-9a-f]{20}$/.test(id)) return new Response('bad', { status: 400 });
    const src = SR2.url + '/a/' + id + '.bin?k=' + encodeURIComponent(SR2.k) + '&v=' + encodeURIComponent(u.searchParams.get('v') || '');
    const h = await readHead(src), { cs, n } = h, E = cs + 16, nch = Math.max(1, Math.ceil(n / cs)), encTotal = 28 + n + 16 * nch;
    const rh = req.headers.get('range'), m = rh && /bytes=(\d*)-(\d*)/.exec(rh);
    const a = m && m[1] ? Number(m[1]) : 0;
    const b = Math.min(m && m[2] ? Number(m[2]) : n - 1, n - 1);
    if (a > b) return new Response('', { status: 416, headers: { 'Content-Range': `bytes */${n}` } });
    const c0 = Math.floor(a / cs), c1 = Math.floor(b / cs);
    const s = 28 + c0 * E, t = Math.min(28 + (c1 + 1) * E, encTotal) - 1;
    const r = await fetch(src, { headers: { Range: `bytes=${s}-${t}` } });
    if (!r.ok) return new Response('src ' + r.status, { status: 502 });
    let skip = r.status === 200 ? s : 0;   // 부분 받기를 안 해 주면 앞을 버림
    const rd = r.body.getReader();
    let buf = new Uint8Array(0), ci = c0;
    const ivOf = i => { const v = h.iv.slice(); const x = (new DataView(v.buffer).getUint32(8) ^ i) >>> 0; new DataView(v.buffer).setUint32(8, x); return v; };
    const body = new ReadableStream({
      async pull(ctl) {
        for (;;) {
          const need = (ci === nch - 1 ? n - ci * cs : cs) + 16;
          if (buf.length >= need) {
            const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivOf(ci) }, SKEY, buf.slice(0, need)));
            buf = buf.slice(need);
            const s0 = ci === c0 ? a - c0 * cs : 0, e0 = ci === c1 ? b - c1 * cs + 1 : pt.length;
            ctl.enqueue(pt.slice(s0, e0));
            if (++ci > c1) { ctl.close(); rd.cancel().catch(() => {}); }
            return;
          }
          const { done, value } = await rd.read();
          if (done) { ctl.close(); return; }
          let v = value;
          if (skip) { const k = Math.min(skip, v.length); v = v.slice(k); skip -= k; }
          buf = join(buf, v);
        }
      },
      cancel() { rd.cancel().catch(() => {}); },
    });
    const hd = { 'Content-Type': 'audio/mp4', 'Content-Length': String(b - a + 1), 'Accept-Ranges': 'bytes' };
    if (rh) hd['Content-Range'] = `bytes ${a}-${b}/${n}`;
    return new Response(body, { status: rh ? 206 : 200, headers: hd });
  } catch (err) {
    return new Response('stream ' + err.message, { status: 502 });
  }
}
