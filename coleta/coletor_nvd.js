// Coletor executado no navegador, na origem services.nvd.nist.gov (mesma origem da API).
// Guarda apenas os campos usados no protótipo e respeita o limite público da NVD
// (5 requisições a cada 30 s). Os dados são exportados compactados (gzip + base64).
window.__pp = {cve: [], rec: [], ana: [], rej: [], src: {}, log: [], done: false, pages: 0, errors: 0, t0: Date.now()};
const S = window.__pp;
const wk = new Worker(URL.createObjectURL(new Blob(["onmessage = e => setTimeout(() => postMessage(e.data), e.data.ms)"], {type: 'text/javascript'})));
let seq = 0; const waits = {}; wk.onmessage = e => { const f = waits[e.data.id]; delete waits[e.data.id]; f && f(); };
const sleep = ms => new Promise(r => { const id = ++seq; waits[id] = r; wk.postMessage({id, ms}); });
function windows(a, b) { const out = []; let s = new Date(a + 'T00:00:00Z'); const end = new Date(b + 'T00:00:00Z');
  while (s <= end) { let e = new Date(s.getTime() + 119*86400000); if (e > end) e = end; out.push([s.toISOString().slice(0,10), e.toISOString().slice(0,10)]); s = new Date(e.getTime() + 86400000); } return out; }
function srcIdx(s) { if (!(s in S.src)) S.src[s] = Object.keys(S.src).length; return S.src[s]; }
function code(v) { const m = {}; for (const p of v.split('/')) { const [k, x] = p.split(':'); m[k] = x; } return ['AV','AC','PR','UI','S','C','I','A'].map(k => m[k] || '?').join(''); }
function vec(details, type) { const d = details.find(x => x.action === 'Added' && x.type === type); if (!d) return ''; const m = String(d.newValue || '').match(/(AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HLN]\/I:[HLN]\/A:[HLN])/); return m ? code(m[1]) : ''; }
function cwes(details) { return [...new Set(details.filter(x => x.action === 'Added' && x.type === 'CWE').map(x => (String(x.newValue||'').match(/CWE-(\d+)|NVD-CWE-(Other|noinfo)/)||[])).map(m => m[1] || (m[2] ? m[2][0] : '')).filter(Boolean))].join('.'); }
async function getJ(url) { for (let t = 0; t < 8; t++) { try { const r = await fetch(url); if (r.ok) return await r.json(); S.log.push('http ' + r.status); } catch (e) { S.log.push('err ' + e); } S.errors++; await sleep(35000); } throw new Error('falhou ' + url); }
async function pag(base, a, b, size, f, label) { for (const [s, e] of windows(a, b)) { let start = 0, total = 1; while (start < total) { const t1 = Date.now(); const j = await getJ(base(s, e) + `&resultsPerPage=${size}&startIndex=${start}`); total = j.totalResults; f(j); start += size; S.pages++; S.log.push(`${label} ${s} ${Math.min(start,total)}/${total} ${Math.round((Date.now()-t1)/1000)}s`); const el = Date.now() - t1; await sleep(Math.max(0, 6500 - el) + 300); } } }
const hist = ev => (s, e) => `/rest/json/cvehistory/2.0?eventName=${encodeURIComponent(ev)}&changeStartDate=${s}T00:00:00.000&changeEndDate=${e}T23:59:59.999`;
const cves = (s, e) => `/rest/json/cves/2.0?pubStartDate=${s}T00:00:00.000&pubEndDate=${e}T23:59:59.999`;
const fCve = j => { for (const v of j.vulnerabilities) { const c = v.cve; S.cve.push([c.id, c.published.slice(0, 10), srcIdx(c.sourceIdentifier || ''), c.vulnStatus === 'Rejected' ? 1 : 0]); } };
const fRec = j => { for (const x of j.cveChanges) { const c = x.change, d = c.details || []; S.rec.push([c.cveId, c.created.slice(0, 10), srcIdx(c.sourceIdentifier || ''), vec(d, 'CVSS V3.1') || vec(d, 'CVSS V3.0'), cwes(d), d.some(z => z.type === 'CVSS V4.0') ? 1 : 0]); } };
const fAna = j => { for (const x of j.cveChanges) { const c = x.change, d = c.details || []; S.ana.push([c.cveId, c.created.slice(0, 10), vec(d, 'CVSS V3.1') || vec(d, 'CVSS V3.0'), cwes(d)]); } };
const fRej = j => { for (const x of j.cveChanges) S.rej.push([x.change.cveId, x.change.created.slice(0, 10)]); };
async function gz(bytes) { const cs = new CompressionStream('gzip'); const w = cs.writable.getWriter(); w.write(bytes); w.close(); const rd = cs.readable.getReader(); const parts = []; let n = 0; for (;;) { const {done, value} = await rd.read(); if (done) break; parts.push(value); n += value.length; } const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; }
function b64(u8) { let s = ''; const CH = 0x8000; for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH)); return btoa(s); }
window.__exp = {};
window.__prep = async (nome, obj) => { window.__exp[nome] = b64(await gz(new TextEncoder().encode(JSON.stringify(obj)))); return window.__exp[nome].length; };
window.__jobs = {pag, hist, cves, fCve, fRec, fAna, fRej};
