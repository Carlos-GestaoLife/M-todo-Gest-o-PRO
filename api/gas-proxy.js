// =============================================================================
// /api/gas-proxy.js
// =============================================================================
// Proxy de cache (Upstash Redis) na frente do Google Apps Script.
// Adaptado ao estilo do api/login.js: Node Runtime, parsing manual de body
// via stream, e validação extra de sessão via lib/auth.js.
//
// Como funciona:
//   - Front (plano-de-acao.html, formulario.html) faz POST pra /api/gas-proxy
//     com o mesmo formato que mandava pro Apps Script (action + payload + token).
//   - O middleware.js já garante que só usuários logados chegam aqui.
//   - Reads cacheáveis → Redis. HIT: resposta instantânea. MISS: chama GAS,
//     salva no Redis com TTL e devolve.
//   - Writes → vão direto pro GAS e invalidam o cache das reads relacionadas.
//   - Actions não mapeadas (auth, debug, etc.) passam direto sem cachear.
//   - Falha de Redis nunca quebra: cai pro GAS direto. Sistema fica "como antes".
//
// Env vars necessárias (Settings → Environment Variables no Vercel):
//   GAS_WEBHOOK_URL              — URL completa do Apps Script (com /exec)
//   KV_REST_API_URL              — auto-injetada (Redis Oficial Vercel)
//   KV_REST_API_TOKEN            — auto-injetada (Redis Oficial Vercel)
//   AUTH_SECRET                  — já existe no projeto (usada pelo login)
// (Fallback automático pra UPSTASH_REDIS_REST_URL/TOKEN se for esse o Redis.)
// =============================================================================

import { COOKIE_NAME, readCookie, verifySession } from "../lib/auth.js";

export const config = { runtime: "nodejs" };

// ---------- Mapeamento de actions ----------------------------------------
// READ: cacheia com TTL em segundos.
const READ_ACTIONS = {
  "listar-planos":               180,
  "listar-empresas":             120,
  "listar-empresas-crm":         120,
  "listar-base":                 600,
  "listar-inadimplencia":        600,
  "listar-anotacoes":            120,
  "listar-tarefas-cliente":      120,
  "listar-todos-compromissos":   120,
  "listar-consultores":          3600,
  "listar-eventos-calendar":     60,
  "buscar-empresa-diagnostico":  300,
  "buscar-diagnostico-completo": 300,
};

// WRITE: vai direto pro GAS + invalida cache das reads relacionadas (por prefixo).
const INVALIDATIONS = {
  "salvar-empresa-crm":           ["listar-empresas-crm", "listar-empresas"],
  "marcar-contato":               ["listar-empresas-crm", "listar-empresas"],
  "marcar-onboarding":            ["listar-empresas-crm", "listar-empresas"],
  "salvar-plano":                 ["listar-planos", "listar-todos-compromissos", "listar-empresas"],
  "excluir-plano":                ["listar-planos", "listar-todos-compromissos", "listar-empresas"],
  "sincronizar-base-clientes":    ["listar-base"],
  "sincronizar-inadimplencia":    ["listar-inadimplencia"],
  "salvar-anotacao":              ["listar-anotacoes"],
  "excluir-anotacao":             ["listar-anotacoes"],
  "salvar-tarefa-cliente":        ["listar-tarefas-cliente"],
  "atualizar-status-compromisso": ["listar-todos-compromissos", "listar-planos"],
  "criar-evento-calendar":        ["listar-eventos-calendar"],
  "editar-evento-calendar":       ["listar-eventos-calendar"],
  "excluir-evento-calendar":      ["listar-eventos-calendar"],
};

// ---------- Helpers ------------------------------------------------------

// Lê body do request via stream (mesmo padrão do api/login.js)
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 5e6) {
        reject(new Error("payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

// Chamada Redis via REST. Funciona tanto com Upstash quanto com "Official Redis for Vercel" (KV_REST_*).
// Retorna null em qualquer erro (failsafe — erro de Redis nunca quebra a requisição).
async function redisCmd(...args) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(args),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.result;
  } catch (err) {
    console.error("[gas-proxy:redis]", err.message);
    return null;
  }
}

async function cacheGet(key) {
  const raw = await redisCmd("GET", key);
  return raw || null;
}

async function cacheSet(key, value, ttlSec) {
  return redisCmd("SET", key, value, "EX", ttlSec);
}

// Invalida todas as chaves que casam com um prefixo (SCAN + DEL em batch)
async function cacheInvalidatePrefix(prefix) {
  let cursor = "0";
  let total = 0;
  do {
    const r = await redisCmd("SCAN", cursor, "MATCH", `${prefix}:*`, "COUNT", "200");
    if (!r || !Array.isArray(r)) break;
    cursor = r[0];
    const keys = r[1] || [];
    if (keys.length) {
      await redisCmd("DEL", ...keys);
      total += keys.length;
    }
  } while (cursor !== "0" && total < 2000);
  return total;
}

function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h) + s.charCodeAt(i);
    h |= 0;
  }
  return h.toString(36);
}

// Constrói chave de cache a partir da action + payload (ignora token + auth interna)
function buildCacheKey(action, payload) {
  const clone = { ...(payload || {}) };
  delete clone.token;
  delete clone._user; // não polui a chave com identidade do usuário
  const ordered = Object.keys(clone).sort().reduce((acc, k) => {
    acc[k] = clone[k];
    return acc;
  }, {});
  return `${action}:${hashStr(JSON.stringify(ordered))}`;
}

// Chama o Apps Script (sempre POST + JSON)
async function callGas(payload) {
  const url = process.env.GAS_WEBHOOK_URL;
  if (!url) throw new Error("GAS_WEBHOOK_URL não configurada");
  const res = await fetch(url, {
    method: "POST",
    redirect: "follow",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.text();
}

// ---------- Handler ------------------------------------------------------

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, error: "method_not_allowed" });
    return;
  }

  // Identifica o usuário logado (defesa em profundidade — o middleware já validou)
  let loggedUser = null;
  try {
    const secret = process.env.AUTH_SECRET;
    if (secret) {
      const token = readCookie(req.headers.cookie, COOKIE_NAME);
      const session = token ? await verifySession(token, secret) : null;
      if (session) loggedUser = session.user;
    }
  } catch (err) {
    console.error("[gas-proxy:auth]", err.message);
  }
  // Se chegou até aqui sem usuário, é estranho (middleware deveria ter bloqueado),
  // mas seguimos — o GAS tem o próprio token de validação.

  // Parse body
  let payload;
  try {
    payload = await readJson(req);
  } catch {
    res.status(400).json({ ok: false, error: "invalid_body" });
    return;
  }

  const action = payload?.action;
  if (!action) {
    res.status(400).json({ ok: false, error: "missing_action" });
    return;
  }

  // Anexa identidade do usuário logado pro GAS poder logar quem fez o quê
  if (loggedUser) payload._user = loggedUser;

  // -------- WRITE: chama GAS + invalida cache ---------------------------
  if (INVALIDATIONS[action]) {
    let body;
    try {
      body = await callGas(payload);
    } catch (err) {
      res.status(502).json({ ok: false, error: "gas_failed", detail: err.message });
      return;
    }
    INVALIDATIONS[action].forEach((prefix) => {
      cacheInvalidatePrefix(prefix).catch(() => {});
    });
    res.setHeader("Content-Type", "application/json");
    res.setHeader("X-Cache", "BYPASS-WRITE");
    res.status(200).send(body);
    return;
  }

  // -------- READ: checa Redis, senão GAS + cacheia ----------------------
  if (READ_ACTIONS[action]) {
    const ttl = READ_ACTIONS[action];
    const key = buildCacheKey(action, payload);

    const cached = await cacheGet(key);
    if (cached !== null) {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("X-Cache", "HIT");
      res.status(200).send(cached);
      return;
    }

    let body;
    try {
      body = await callGas(payload);
    } catch (err) {
      res.status(502).json({ ok: false, error: "gas_failed", detail: err.message });
      return;
    }

    // Só cacheia respostas de sucesso
    let cacheable = true;
    try {
      const parsed = JSON.parse(body);
      if (parsed && parsed.ok === false) cacheable = false;
    } catch {
      cacheable = false;
    }
    if (cacheable) cacheSet(key, body, ttl).catch(() => {});

    res.setHeader("Content-Type", "application/json");
    res.setHeader("X-Cache", "MISS");
    res.status(200).send(body);
    return;
  }

  // -------- UNCACHED: passa direto (login interno do GAS, init, debug...) ---
  let body;
  try {
    body = await callGas(payload);
  } catch (err) {
    res.status(502).json({ ok: false, error: "gas_failed", detail: err.message });
    return;
  }
  res.setHeader("Content-Type", "application/json");
  res.setHeader("X-Cache", "BYPASS-UNCACHED");
  res.status(200).send(body);
}