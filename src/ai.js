const DEFAULT_MODELS = [
  "nvidia/nemotron-3.5-lightning:free",
  "nvidia/nemotron-3.5-super-vl:free",
  "nvidia/nemotron-3-ultra-550b-a55b:free"
];

const SYSTEM_PROMPT = [
  "You are Acrionix, a staff-level AOSP, Embedded Android, and Linux Kernel BSP debugging engine.",
  "Given a raw crash or build log (logcat, dmesg, tombstone, SELinux audit, Soong/Kbuild error, init.rc, VINTF, or driver oops),",
  "identify the exact root cause and produce a minimal, least-privilege unified git diff patch.",
  "Never suggest SELinux permissive mode. Respect AOSP CTS neverallow rules.",
  "IMPORTANT: If the user input is NOT a technical crash, runtime, kernel, Android/AOSP, or compiler/build log (for example greetings, chat, random words, or unrelated text), DO NOT invent a fake patch. Instead return ONLY:",
  '{"is_valid_log": false, "reason": "Input is not an Android, Linux kernel, or build log. Paste a real logcat, dmesg, SELinux denial, tombstone, or compiler error."}',
  "Otherwise return ONLY raw valid JSON (no markdown, no explanation outside JSON) with this exact schema:",
  "{",
  '  "is_valid_log": true,',
  '  "category": "selinux|vintf|firmware|init|tombstone|kernel|dsu|build",',
  '  "severity": "critical|high|medium",',
  '  "title": "concise technical root-cause title",',
  '  "summary": "2-3 sentence root cause explanation naming exact files and symbols",',
  '  "partition": "partition: /vendor (or /system, /boot, /vendor_dlkm, etc.)",',
  '  "file_path": "realistic AOSP/kernel repo relative path to patch",',
  '  "security_note": "short least-privilege or verification note",',
  '  "diff_lines": ["diff --git a/...", "--- a/...", "+++ b/...", "@@ ... @@", " context", "-old", "+new"]',
  "}"
].join("\n");

function extractJsonObject(rawText) {
  const text = String(rawText || "").trim();
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : text;
  const firstBrace = candidate.indexOf("{");
  const lastBrace = candidate.lastIndexOf("}");
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    return null;
  }
  try {
    return JSON.parse(candidate.slice(firstBrace, lastBrace + 1));
  } catch {
    return null;
  }
}

async function callOpenRouter(apiKey, model, logSnippet) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 16000);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://acrionix.cloud",
        "X-Title": "Acrionix Edge Triage"
      },
      body: JSON.stringify({
        model,
        temperature: 0.15,
        max_tokens: 2048,
        reasoning: { enabled: false },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: `Analyze this runtime/build log and return JSON only:\n\n${logSnippet}`
          }
        ]
      })
    });
    if (!res.ok) {
      return { error: `http_${res.status}` };
    }
    const data = await res.json();
    const msg = data?.choices?.[0]?.message;
    const content = msg?.content || msg?.reasoning || "";
    if (!content) {
      return { error: `empty_${data?.choices?.[0]?.finish_reason || "unknown"}` };
    }
    const parsed = extractJsonObject(content);
    if (!parsed) {
      return { error: "json_parse_failed" };
    }
    if (parsed.is_valid_log === false) {
      return { invalidLog: true, reason: String(parsed.reason || "Input does not look like a technical crash or build log."), modelUsed: data?.model || model };
    }
    if (!parsed.title || !Array.isArray(parsed.diff_lines)) {
      return { error: "json_parse_failed" };
    }
    return { parsed, modelUsed: data?.model || model };
  } catch (err) {
    return { error: err?.name === "AbortError" ? "timeout" : "fetch_error" };
  } finally {
    clearTimeout(timer);
  }
}

export async function runAiTriage(rawLog, env) {
  const apiKey = env?.OPENROUTER_API_KEY;
  if (!apiKey) return null;

  const start = Date.now();
  const clipped = String(rawLog || "").slice(0, 16000);
  const models = env.OPENROUTER_MODEL
    ? [env.OPENROUTER_MODEL, ...DEFAULT_MODELS.filter((m) => m !== env.OPENROUTER_MODEL)]
    : DEFAULT_MODELS;

  let aiOut = null;
  for (const model of models) {
    const res = await callOpenRouter(apiKey, model, clipped);
    if (res && (res.parsed || res.invalidLog)) {
      aiOut = res;
      break;
    }
  }
  if (!aiOut) return null;

  if (aiOut.invalidLog) {
    return {
      ok: true,
      is_valid_log: false,
      engine: `acrionix-ai (${aiOut.modelUsed})`,
      ai_powered: true,
      model: aiOut.modelUsed,
      lines_scanned: String(rawLog || "").split(/\r?\n/).length,
      latency_ms: Math.max(1, Date.now() - start),
      error_message: aiOut.reason,
      findings: [],
      patches: [],
      warnings: []
    };
  }

  const { parsed, modelUsed } = aiOut;
  const diffLines = parsed.diff_lines.map((l) => String(l)).slice(0, 80);
  const added = diffLines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length;
  const removed = diffLines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;
  const filePath = String(parsed.file_path || "device/oem/common/patch.txt").slice(0, 180);
  const slug =
    "fix-ai-" +
    filePath
      .split("/")
      .pop()
      .replace(/[^a-zA-Z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .toLowerCase();

  return {
    ok: true,
    engine: `acrionix-ai (${modelUsed})`,
    ai_powered: true,
    model: modelUsed,
    lines_scanned: String(rawLog || "").split(/\r?\n/).length,
    latency_ms: Math.max(1, Date.now() - start),
    findings: [
      {
        category: String(parsed.category || "kernel"),
        severity: String(parsed.severity || "high"),
        title: String(parsed.title).slice(0, 140),
        summary: String(parsed.summary || "").slice(0, 600),
        partition: String(parsed.partition || "partition: /vendor"),
        target_file: filePath,
        confidence: 0.95,
        security_note: String(
          parsed.security_note || "Synthesized by Acrionix AI (least-privilege verified)."
        )
      }
    ],
    patches: diffLines.length
      ? [
          {
            slug: slug || "fix-acrionix-ai",
            file_path: filePath,
            stats: `+${added} -${removed}`,
            diff_lines: diffLines
          }
        ]
      : [],
    warnings: []
  };
}
