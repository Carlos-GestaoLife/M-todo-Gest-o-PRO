// =============================================================================
// /api/auth/google.js
// =============================================================================
// Recebe o ID Token JWT do Google (do botão Sign-In) e cria a sessão gl_session.
// Valida via endpoint público tokeninfo do Google (sem dependências).
//
// Env vars:
//   AUTH_SECRET           — usado pra assinar a sessão (já existe)
//   GOOGLE_CLIENT_ID      — OAuth Client ID do Google Cloud
//   ALLOWED_EMAILS        — lista de emails autorizados, separados por vírgula
//                           (ex: "carlos@gmail.com,matheus@gmail.com")
//   ALLOWED_DOMAIN        — (opcional) restringe por domínio Workspace
//                           (ex: "gestaolife.com.br")
//   Pelo menos UMA das duas (ALLOWED_EMAILS ou ALLOWED_DOMAIN) precisa estar setada.
// =============================================================================

import { buildSessionCookie, signSession } from "../../lib/auth.js";

export const config = { runtime: "nodejs" };

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e5) {
        reject(new Error("payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { resolve({}); }
    });
    req.on("error", reject);
  });
}

function parseList(raw) {
  return String(raw || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, error: "method_not_allowed" });
    return;
  }

  const secret = process.env.AUTH_SECRET;
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const allowedEmails = parseList(process.env.ALLOWED_EMAILS);
  const allowedDomain = String(process.env.ALLOWED_DOMAIN || "").trim().toLowerCase();

  if (!secret || !clientId) {
    res.status(500).json({ ok: false, error: "server_not_configured" });
    return;
  }
  if (!allowedEmails.length && !allowedDomain) {
    res.status(500).json({ ok: false, error: "no_allowlist_configured" });
    return;
  }

  let payload;
  try { payload = await readJson(req); }
  catch { res.status(400).json({ ok: false, error: "invalid_body" }); return; }

  const credential = String(payload.credential || "");
  if (!credential) {
    res.status(400).json({ ok: false, error: "missing_credential" });
    return;
  }

  // Valida o ID token via endpoint público da Google (sem deps)
  let info;
  try {
    const r = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`
    );
    info = await r.json();
  } catch (err) {
    res.status(502).json({ ok: false, error: "google_unreachable" });
    return;
  }

  if (info.error || !info.email) {
    res.status(401).json({
      ok: false,
      error: "invalid_token",
      detail: info.error_description || info.error || "no_email",
    });
    return;
  }

  // Confere que o token foi emitido pra ESTE app (audience = nosso client_id)
  if (info.aud !== clientId) {
    res.status(401).json({ ok: false, error: "wrong_audience" });
    return;
  }

  // Email precisa estar verificado pelo Google
  const verified = info.email_verified === "true" || info.email_verified === true;
  if (!verified) {
    res.status(401).json({ ok: false, error: "email_not_verified" });
    return;
  }

  const email = String(info.email).toLowerCase();
  const nome = info.name || email.split("@")[0];

  // Allowlist: passa se email tá na lista OU se domínio bate
  const passList = allowedEmails.includes(email);
  const passDomain = allowedDomain && email.endsWith("@" + allowedDomain);
  if (!passList && !passDomain) {
    res.status(403).json({ ok: false, error: "email_not_allowed", email });
    return;
  }

  // Cria sessão (cookie gl_session) — guarda email como identificador
  const token = await signSession(email, secret);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  res.status(200).json({ ok: true, user: email, name: nome });
}