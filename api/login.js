import {
  buildSessionCookie,
  checkPassword,
  parseUsers,
  signSession,
} from "../lib/auth.js";

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
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }

  const secret = process.env.AUTH_SECRET;
  const users = parseUsers(process.env.AUTH_USERS);

  if (!secret || Object.keys(users).length === 0) {
    res.status(500).json({ error: "server_not_configured" });
    return;
  }

  let payload;
  try {
    payload = await readJson(req);
  } catch {
    res.status(400).json({ error: "invalid_body" });
    return;
  }

  const username = typeof payload.username === "string" ? payload.username.trim() : "";
  const password = typeof payload.password === "string" ? payload.password : "";

  if (!username || !password) {
    res.status(400).json({ error: "missing_credentials" });
    return;
  }

  const expected = users[username];
  if (!expected || !checkPassword(password, expected)) {
    res.status(401).json({ error: "invalid_credentials" });
    return;
  }

  const token = await signSession(username, secret);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  res.status(200).json({ ok: true, user: username });
}