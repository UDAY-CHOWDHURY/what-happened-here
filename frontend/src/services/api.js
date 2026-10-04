const j = async (r) => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json() }
const post = (u, body) => fetch('/api' + u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(j)
export const uploadFile = (f) => { const fd = new FormData(); fd.append('file', f); return fetch('/api/upload', { method: 'POST', body: fd }).then(j) }
export const uploadSample = (n) => fetch('/api/upload_sample/' + n, { method: 'POST' }).then(j)
export const analyze = (id) => post('/analyze', { id })
export const explain = (id, question) => post('/explain', { id, question })
