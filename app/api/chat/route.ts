import { NextRequest, NextResponse } from "next/server";

// Only allow specific known provider endpoints — never arbitrary URLs (SSRF prevention)
const PROVIDER_ENDPOINTS: Record<string, string> = {
  openai: "https://api.openai.com/v1/chat/completions",
  groq: "https://api.groq.com/openai/v1/chat/completions",
};

const ALLOWED_OPENAI_MODELS = new Set([
  "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "gpt-4-turbo",
]);
const ALLOWED_GROQ_MODELS = new Set([
  "llama3-8b-8192", "llama3-70b-8192", "mixtral-8x7b-32768",
  "llama-3.1-8b-instant", "llama-3.3-70b-versatile",
]);

function getAllowedModels(provider: string): Set<string> {
  if (provider === "openai") return ALLOWED_OPENAI_MODELS;
  if (provider === "groq") return ALLOWED_GROQ_MODELS;
  return new Set();
}

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { message, apiKey, provider, model, systemPrompt } = body as {
    message?: unknown;
    apiKey?: unknown;
    provider?: unknown;
    model?: unknown;
    systemPrompt?: unknown;
  };

  // Input validation
  if (typeof message !== "string" || !message.trim()) {
    return NextResponse.json({ error: "message is required" }, { status: 400 });
  }
  if (typeof provider !== "string" || !PROVIDER_ENDPOINTS[provider]) {
    return NextResponse.json({ error: "Invalid provider. Must be 'openai' or 'groq'." }, { status: 400 });
  }
  if (typeof apiKey !== "string" || !apiKey.trim()) {
    return NextResponse.json({ error: "apiKey is required" }, { status: 400 });
  }

  // Validate API key format (basic sanity check, not exposing in logs)
  const trimmedKey = apiKey.trim();
  if (provider === "openai" && !trimmedKey.startsWith("sk-")) {
    return NextResponse.json({ error: "Invalid OpenAI API key format." }, { status: 400 });
  }
  if (provider === "groq" && !trimmedKey.startsWith("gsk_")) {
    return NextResponse.json({ error: "Invalid Groq API key format." }, { status: 400 });
  }

  // Validate model
  const resolvedModel = typeof model === "string" ? model : "";
  const allowedModels = getAllowedModels(provider);
  const finalModel = allowedModels.has(resolvedModel)
    ? resolvedModel
    : provider === "openai"
    ? "gpt-4o-mini"
    : "llama3-8b-8192";

  const safeSystemPrompt =
    typeof systemPrompt === "string" && systemPrompt.trim()
      ? systemPrompt.trim().slice(0, 2000)
      : "You are a helpful, harmless, and honest assistant.";

  const endpoint = PROVIDER_ENDPOINTS[provider];

  try {
    const apiRes = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${trimmedKey}`,
      },
      body: JSON.stringify({
        model: finalModel,
        messages: [
          { role: "system", content: safeSystemPrompt },
          { role: "user", content: message.slice(0, 8000) },
        ],
        max_tokens: 1024,
        temperature: 0.7,
      }),
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text().catch(() => "");
      // Don't expose raw error body which might contain sensitive info
      const statusMsg = apiRes.status === 401
        ? "Invalid API key or unauthorized."
        : apiRes.status === 429
        ? "Rate limit exceeded. Please wait and try again."
        : apiRes.status === 403
        ? "Access forbidden. Check your API key permissions."
        : `API request failed (HTTP ${apiRes.status}).`;
      console.error(`[SecureLLM Chat] Provider error ${apiRes.status}: ${errText.slice(0, 200)}`);
      return NextResponse.json({ error: statusMsg }, { status: 502 });
    }

    const data = await apiRes.json();
    const response: string = data?.choices?.[0]?.message?.content ?? "[No response from model]";

    return NextResponse.json({ response });
  } catch (err) {
    console.error("[SecureLLM Chat] Fetch error:", err instanceof Error ? err.message : "unknown");
    return NextResponse.json(
      { error: "Could not reach AI provider. Check network and API key." },
      { status: 502 }
    );
  }
}
