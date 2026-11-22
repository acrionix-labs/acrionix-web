import { runEdgeTriage } from "./triage.js";

const ALLOWED_ORIGINS = new Set([
  "https://acrionix.cloud",
  "https://www.acrionix.cloud",
  "https://docs.acrionix.net"
]);

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const isLocal = origin.startsWith("http://127.0.0.1") || origin.startsWith("http://localhost");
  const allowOrigin = ALLOWED_ORIGINS.has(origin) || isLocal ? origin : "https://acrionix.cloud";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function withSecurityHeaders(response, cacheControl) {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  if (cacheControl) {
    headers.set("Cache-Control", cacheControl);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

async function serveHtmlAsset(env, request, assetPath) {
  const assetUrl = new URL(assetPath, request.url);
  const res = await env.ASSETS.fetch(new Request(assetUrl.toString(), { method: "GET" }));
  const headers = new Headers(res.headers);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return withSecurityHeaders(
    new Response(res.body, { status: res.status, headers }),
    "public, max-age=300"
  );
}

async function handleBetaSignup(request, env) {
  const cors = corsHeaders(request);

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { ok: false, error: "Invalid JSON payload." },
      { status: 400, headers: cors }
    );
  }

  const email = String(body?.email || "").trim().slice(0, 160);
  const target = String(body?.target || "").trim().slice(0, 160);
  const plan = String(body?.plan || "Public Beta v0.4").trim().slice(0, 80);
  const source = String(body?.source || "web-modal").trim().slice(0, 40);

  if (source !== "github-oauth" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return Response.json(
      { ok: false, error: "Please enter a valid work email address." },
      { status: 400, headers: cors }
    );
  }

  const country = request.cf?.country || "unknown";
  const timestamp = new Date().toISOString();

  let delivered = false;
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    const lines = [
      "<b>New Acrionix Beta Request</b>",
      `<b>Plan:</b> ${escapeHtml(plan)}`,
      `<b>Source:</b> ${escapeHtml(source)}`,
      email ? `<b>Email:</b> <code>${escapeHtml(email)}</code>` : null,
      target ? `<b>Target:</b> <code>${escapeHtml(target)}</code>` : null,
      `<b>Region:</b> ${escapeHtml(country)}`,
      `<b>Time:</b> ${escapeHtml(timestamp)}`
    ].filter(Boolean);

    try {
      const tgRes = await fetch(
        `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: env.TELEGRAM_CHAT_ID,
            text: lines.join("\n"),
            parse_mode: "HTML",
            disable_web_page_preview: true
          })
        }
      );
      delivered = tgRes.ok;
    } catch {
      delivered = false;
    }
  }

  return Response.json(
    {
      ok: true,
      delivered,
      plan,
      email: email || null,
      timestamp
    },
    { status: 200, headers: cors }
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headerHost = (request.headers.get("host") || "").split(":")[0].toLowerCase();
    const host = (headerHost && headerHost !== "127.0.0.1" && headerHost !== "localhost")
      ? headerHost
      : url.hostname.toLowerCase();
    const path = url.pathname;

    if (host === "www.acrionix.cloud") {
      return Response.redirect(`https://acrionix.cloud${path}${url.search}`, 301);
    }

    if (path === "/health") {
      return Response.json({
        status: "ok",
        service: "acrionix-web",
        host,
        timestamp: new Date().toISOString()
      });
    }

    if (path === "/api/triage") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }
      if (request.method !== "POST") {
        return Response.json(
          { ok: false, error: "Method not allowed." },
          { status: 405, headers: corsHeaders(request) }
        );
      }
      let payload;
      try {
        payload = await request.json();
      } catch {
        return Response.json(
          { ok: false, error: "Invalid JSON payload." },
          { status: 400, headers: corsHeaders(request) }
        );
      }
      const rawLog = String(payload?.log || "");
      if (!rawLog.trim()) {
        return Response.json(
          { ok: false, error: "Field 'log' must be a non-empty string." },
          { status: 400, headers: corsHeaders(request) }
        );
      }
      if (rawLog.length > 131072) {
        return Response.json(
          { ok: false, error: "Log payload exceeds 128 KB edge limit." },
          { status: 413, headers: corsHeaders(request) }
        );
      }
      const result = runEdgeTriage(rawLog);
      return Response.json(result, { status: 200, headers: corsHeaders(request) });
    }

    if (path === "/api/beta") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }
      if (request.method === "POST") {
        return handleBetaSignup(request, env);
      }
      return Response.json(
        { ok: false, error: "Method not allowed." },
        { status: 405, headers: corsHeaders(request) }
      );
    }

    if (path === "/robots.txt" || path === "/sitemap.xml") {
      const staticRes = await env.ASSETS.fetch(request);
      return withSecurityHeaders(staticRes, "public, max-age=3600");
    }

    if (host === "docs.acrionix.net" || path === "/docs" || path.startsWith("/docs/")) {
      return serveHtmlAsset(env, request, "/docs.html");
    }

    if (path === "/" || path === "/index.html") {
      return serveHtmlAsset(env, request, "/landing.html");
    }

    const assetRes = await env.ASSETS.fetch(request);
    if (assetRes.status !== 404) {
      return withSecurityHeaders(assetRes, "public, max-age=3600");
    }

    return serveHtmlAsset(env, request, "/landing.html");
  }
};
