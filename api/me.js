// =============================================================================
// /api/me.js
// =============================================================================
// Endpoint que devolve qual usuário está logado neste momento (lê do cookie).
// Usado pelo crm.html pra "single sign-on" — se o usuário já fez login na
// porta de entrada do site (login.html), o CRM pula a tela de login interna
// e usa o mesmo nome de usuário automaticamente.
//
// Retornos:
//   { ok: true, user: "carlos" }    se houver sessão válida
//   { ok: false }                   se não houver cookie ou estiver expirado
//
// Não retorna 401 mesmo quando não logado — sempre 200 com flag ok, pra que
// o cliente não fique recebendo erro no console. O middleware já bloqueia
// requests não autenticadas antes de chegarem aqui, então quando esse handler
// é executado, idealmente sempre temos usuário.
// =============================================================================

import { COOKIE_NAME, readCookie, verifySession } from "../lib/auth.js";

export const config = { runtime: "nodejs" };

export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    res.status(405).json({ ok: false, error: "method_not_allowed" });
    return;
  }

  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    res.status(500).json({ ok: false, error: "server_not_configured" });
    return;
  }

  try {
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) {
      res.status(200).json({ ok: false });
      return;
    }
    const session = await verifySession(token, secret);
    if (!session) {
      res.status(200).json({ ok: false });
      return;
    }
    // Não cacheia esse endpoint — sessão é por usuário
    res.setHeader("Cache-Control", "private, no-store");
    res.status(200).json({ ok: true, user: session.user, expiresAt: session.expiresAt });
  } catch (err) {
    console.error("[api/me]", err.message);
    res.status(200).json({ ok: false });
  }
}