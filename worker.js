// Servidor de guardado y de búsqueda de precios para el Presupuestador Eléctrico (Cloudflare Worker + KV).
//
// Configuración en el Worker (Settings, Variables and Secrets):
//   DATOS            (binding KV)  Espacio de almacenamiento KV. El nombre tiene que ser exactamente DATOS.
//   GOOGLE_CLIENT_ID (texto)       ID de cliente de Google (el mismo que usa index.html).
//   ALLOWED_ORIGINS  (texto)       Sitios que pueden usar el worker, separados por coma.
//                                  Ejemplo: https://tu-usuario.github.io
//   ALLOWED_EMAILS   (texto, opcional) Mails que pueden entrar, separados por coma. Vacío: cualquier cuenta que Google deje pasar.
//   SERPER_API_KEY   (secreto)     Clave de https://serper.dev para buscar precios en Google Shopping.

const KEY = 'estado';
const META_KEY = 'meta';
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_COPIAS = 30;
const CADA_AUTO = 6 * 60 * 60 * 1000; // copia automática: como máximo una cada 6 horas
const CADA_QUITA = 10 * 60 * 1000; // si un cambio quita datos: como máximo una cada 10 minutos
const PRECIOS_TTL = 12 * 60 * 60; // las búsquedas de precios se guardan 12 horas para no gastar consultas

function corsFor(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const open = allowed.length === 0;
  const ok = open || !origin || allowed.includes(origin);
  const headers = { Vary: 'Origin' };
  if (ok && origin) {
    headers['Access-Control-Allow-Origin'] = open ? '*' : origin;
    headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    headers['Access-Control-Max-Age'] = '86400';
  }
  return { ok, headers };
}

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors },
  });
}

/* ---------- Entrada con Google ---------- */
let jwksCache = { t: 0, keys: null };

async function googleKeys() {
  if (jwksCache.keys && Date.now() - jwksCache.t < 60 * 60 * 1000) return jwksCache.keys;
  const r = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  if (!r.ok) throw new Error('No pude leer las claves de Google.');
  const j = await r.json();
  jwksCache = { t: Date.now(), keys: j.keys || [] };
  return jwksCache.keys;
}

function b64u(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Devuelve los datos del usuario si el token de Google es válido, o null.
async function verificarGoogle(token, env) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    const dec = new TextDecoder();
    header = JSON.parse(dec.decode(b64u(parts[0])));
    payload = JSON.parse(dec.decode(b64u(parts[1])));
  } catch (e) {
    return null;
  }
  if (header.alg !== 'RS256') return null;
  const keys = await googleKeys();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) return null;
  if (payload.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') return null;
  if (!payload.exp || payload.exp < Date.now() / 1000) return null;
  if (payload.email_verified === false) return null;
  return payload;
}

function cuentaPermitida(email, env) {
  const lista = String(env.ALLOWED_EMAILS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return lista.length === 0 || lista.includes(String(email || '').toLowerCase());
}

/* ---------- Datos y copias ---------- */
async function leer(env) {
  const raw = await env.DATOS.get(KEY);
  if (!raw) return { version: 0, updated: null, datos: null };
  try {
    return JSON.parse(raw);
  } catch (e) {
    return { version: 0, updated: null, datos: null };
  }
}

function resumen(d) {
  const cat = d && Array.isArray(d.catalogo) ? d.catalogo : [];
  const arch = d && Array.isArray(d.archivo) ? d.archivo : [];
  return { items: cat.length, reales: cat.filter((c) => c && !c.ejemplo).length, pres: arch.length + (d && d.pres ? 1 : 0) };
}

function nuevoId() {
  const rand = Math.random().toString(36).slice(2, 6);
  return new Date().toISOString().replace(/[-:.]/g, '') + '-' + rand;
}

async function crearCopia(env, motivo, datos) {
  const id = nuevoId();
  const t = new Date().toISOString();
  const m = String(motivo || 'copia').slice(0, 80);
  const r = resumen(datos);
  await env.DATOS.put('copia:' + id, JSON.stringify({ id, t, m, r, datos }), { metadata: { t, m, r } });
  await podarCopias(env);
  return { id, t, m, r };
}

async function listarCopias(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.DATOS.list({ prefix: 'copia:', cursor });
    page.keys.forEach((k) => out.push({ id: k.name.slice(6), ...(k.metadata || {}) }));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  out.sort((a, b) => (a.id < b.id ? 1 : -1));
  return out;
}

async function podarCopias(env) {
  const todas = await listarCopias(env);
  const sobran = todas.slice(MAX_COPIAS);
  for (const c of sobran) await env.DATOS.delete('copia:' + c.id);
}

// Copia automática de lo que se va a reemplazar.
async function copiaAutomatica(env, actual, nuevosDatos) {
  if (!actual.datos) return;
  const prev = resumen(actual.datos);
  const next = resumen(nuevosDatos);
  const quita = next.reales < prev.reales || next.items < prev.items || next.pres < prev.pres;
  let meta = {};
  try {
    meta = JSON.parse((await env.DATOS.get(META_KEY)) || '{}') || {};
  } catch (e) {
    meta = {};
  }
  const ahora = Date.now();
  const pasado = ahora - (meta.t || 0);
  if (pasado < (quita ? CADA_QUITA : CADA_AUTO)) return;
  await crearCopia(env, quita ? 'automática: el cambio quita datos' : 'automática', actual.datos);
  await env.DATOS.put(META_KEY, JSON.stringify({ t: ahora }));
}

/* ---------- Precios (Google Shopping vía Serper) ---------- */
// Convierte "$ 12.345,50" o "$12.345" en número.
export function parsePrecio(v) {
  if (typeof v === 'number') return isFinite(v) ? v : 0;
  let s = String(v == null ? '' : v).replace(/[^\d.,]/g, '');
  if (!s) return 0;
  const punto = s.lastIndexOf('.');
  const coma = s.lastIndexOf(',');
  if (punto !== -1 && coma !== -1) {
    const dec = punto > coma ? '.' : ',';
    const mil = dec === '.' ? ',' : '.';
    s = s.split(mil).join('').replace(dec, '.');
  } else if (coma !== -1) {
    const d = s.length - coma - 1;
    s = d <= 2 && s.indexOf(',') === coma ? s.replace(',', '.') : s.split(',').join('');
  } else if (punto !== -1) {
    const d = s.length - punto - 1;
    s = d === 3 || s.indexOf('.') !== punto ? s.split('.').join('') : s;
  }
  const n = parseFloat(s);
  return isFinite(n) ? n : 0;
}

function claveBusqueda(q) {
  return 'precios:' + q.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 100);
}

async function buscarPrecios(request, env, cors) {
  const q = (new URL(request.url).searchParams.get('q') || '').trim().slice(0, 120);
  if (q.length < 2) return json({ error: 'Escribí qué querés buscar.' }, 400, cors);
  if (!env.SERPER_API_KEY) return json({ error: 'Falta el secreto SERPER_API_KEY en el worker. Los pasos están en el README.' }, 500, cors);

  const ck = claveBusqueda(q);
  const guardado = await env.DATOS.get(ck, 'json');
  if (guardado) return json({ ...guardado, cache: true }, 200, cors);

  let res;
  try {
    res = await fetch('https://google.serper.dev/shopping', {
      method: 'POST',
      headers: { 'X-API-KEY': env.SERPER_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ q, gl: 'ar', hl: 'es', num: 20 }),
    });
  } catch (e) {
    return json({ error: 'No pude conectar con el buscador de precios.' }, 502, cors);
  }
  if (res.status === 401 || res.status === 403) return json({ error: 'La clave de Serper no es válida. Revisá SERPER_API_KEY.' }, 502, cors);
  if (res.status === 402 || res.status === 429) return json({ error: 'Se acabaron las consultas de Serper (o van muy rápido). Probá más tarde.' }, 502, cors);
  if (!res.ok) return json({ error: 'El buscador de precios respondió ' + res.status + '.' }, 502, cors);

  let j = {};
  try {
    j = await res.json();
  } catch (e) {
    return json({ error: 'El buscador de precios devolvió algo ilegible.' }, 502, cors);
  }
  const resultados = (Array.isArray(j.shopping) ? j.shopping : [])
    .map((r) => ({ titulo: String(r.title || '').slice(0, 200), tienda: String(r.source || '').slice(0, 60), precio: parsePrecio(r.price), link: String(r.link || '') }))
    .filter((r) => r.precio > 0 && r.titulo)
    .slice(0, 20);
  const out = { q, t: new Date().toISOString(), resultados };
  if (resultados.length) {
    try {
      await env.DATOS.put(ck, JSON.stringify(out), { expirationTtl: PRECIOS_TTL });
    } catch (e) {}
  }
  return json(out, 200, cors);
}

/* ---------- Rutas ---------- */
export default {
  async fetch(request, env) {
    const cors = corsFor(request, env);
    if (!cors.ok) return json({ error: 'Este sitio no está permitido en ALLOWED_ORIGINS.' }, 403, cors.headers);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors.headers });

    const path = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
    const H = cors.headers;

    try {
      if (!env.DATOS) return json({ error: 'Falta el espacio KV. Agregalo como binding con el nombre DATOS.' }, 500, H);
      if (!env.GOOGLE_CLIENT_ID) return json({ error: 'Falta la variable GOOGLE_CLIENT_ID en el worker.' }, 500, H);

      const m = /^Bearer (.+)$/.exec(request.headers.get('Authorization') || '');
      const user = m ? await verificarGoogle(m[1], env) : null;
      if (!user) return json({ error: 'Tu sesión de Google venció o no es válida. Entrá de nuevo.' }, 401, H);
      if (!cuentaPermitida(user.email, env)) {
        return json({ error: 'La cuenta ' + (user.email || '') + ' no tiene acceso a esta página.', codigo: 'cuenta' }, 403, H);
      }

      if (request.method === 'GET' && (path === '/salud' || path === '/')) return json({ ok: true }, 200, H);

      if (request.method === 'GET' && path === '/precios') return await buscarPrecios(request, env, H);

      if (request.method === 'GET' && path === '/datos') return json(await leer(env), 200, H);

      if (request.method === 'PUT' && path === '/datos') {
        const text = await request.text();
        if (text.length > MAX_BYTES) return json({ error: 'Los datos son demasiado grandes.' }, 413, H);
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          return json({ error: 'El cuerpo no es JSON válido.' }, 400, H);
        }
        if (!body || typeof body.datos !== 'object' || body.datos === null || !Number.isInteger(body.base)) {
          return json({ error: 'Faltan datos o la versión base.' }, 400, H);
        }
        const actual = await leer(env);
        if (actual.version !== body.base) {
          return json({ error: 'Conflicto: los datos cambiaron desde otro lugar.', ...actual }, 409, H);
        }
        try {
          await copiaAutomatica(env, actual, body.datos);
        } catch (e) {} // si la copia falla, el guardado sigue igual
        const nuevo = { version: actual.version + 1, updated: new Date().toISOString(), datos: body.datos };
        await env.DATOS.put(KEY, JSON.stringify(nuevo));
        return json({ version: nuevo.version, updated: nuevo.updated }, 200, H);
      }

      if (path === '/copias' && request.method === 'GET') return json({ copias: await listarCopias(env) }, 200, H);

      if (path === '/copias' && request.method === 'POST') {
        const text = await request.text();
        if (text.length > MAX_BYTES) return json({ error: 'Los datos son demasiado grandes.' }, 413, H);
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          return json({ error: 'El cuerpo no es JSON válido.' }, 400, H);
        }
        if (!body || typeof body.datos !== 'object' || body.datos === null) return json({ error: 'Faltan los datos de la copia.' }, 400, H);
        return json(await crearCopia(env, body.motivo, body.datos), 200, H);
      }

      const cm = /^\/copias\/([0-9A-Za-z-]+)$/.exec(path);
      if (cm && request.method === 'GET') {
        const c = await env.DATOS.get('copia:' + cm[1], 'json');
        if (!c) return json({ error: 'No encontré esa copia.' }, 404, H);
        return json(c, 200, H);
      }
      if (cm && request.method === 'DELETE') {
        await env.DATOS.delete('copia:' + cm[1]);
        return json({ ok: true }, 200, H);
      }

      return json({ error: 'Ruta no encontrada.' }, 404, H);
    } catch (e) {
      return json({ error: e.message || 'Error inesperado.' }, 500, H);
    }
  },
};
