import { COOKIE_NAME, readCookie, verifySession } from "./lib/auth.js";

export const config = {
  matcher: [
    // Rotas SEM proteção de login:
    //   - assets internos (_next/, _vercel/, favicon, robots)
    //   - telas de auth (login, api/login, api/auth/google)
    //   - páginas públicas pra cliente (formulario, quadro-execucao, rascunho-perguntas)
    //   - api/gas-proxy (pra essas páginas conseguirem chamar o GAS)
    "/((?!_next/|_vercel/|favicon\\.ico|robots\\.txt|login\\.html|login$|api/login|api/auth/google|formulario|quadro-execucao|rascunho-perguntas|api/gas-proxy).*)",
  ],
};
export default async function middleware(request) {
  const url = new URL(request.url);
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    return new Response(
      "Configuração incompleta: defina AUTH_SECRET no Vercel.",
      { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } },
    );
  }
  const cookieHeader = request.headers.get("cookie");
  const token = readCookie(cookieHeader, COOKIE_NAME);
  const session = token ? await verifySession(token, secret) : null;
  if (session) return;
  const loginUrl = new URL("/login", url);
  if (url.pathname && url.pathname !== "/") {
    loginUrl.searchParams.set("next", url.pathname + url.search);
  }
  return Response.redirect(loginUrl.toString(), 302);
}