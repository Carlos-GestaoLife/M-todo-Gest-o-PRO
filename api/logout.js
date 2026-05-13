import { clearSessionCookie } from "../lib/auth.js";

export const config = { runtime: "nodejs" };

export default function handler(req, res) {
  if (req.method !== "POST" && req.method !== "GET") {
    res.setHeader("Allow", "POST, GET");
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  res.setHeader("Set-Cookie", clearSessionCookie());
  if (req.method === "GET") {
    res.statusCode = 302;
    res.setHeader("Location", "/login");
    res.end();
    return;
  }
  res.status(200).json({ ok: true });
}