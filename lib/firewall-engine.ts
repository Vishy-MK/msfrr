/**
 * Frontend simulation of Input_Firewall-main backend.
 * Mirrors: DecisionEngine, RuleEngine, NormalizationEngine, SanitizationEngine,
 *          PayloadDecoder, MLInjectionDetector
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FirewallMatch {
  id: string;
  name: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  action: string;
  description: string;
}

export interface TraceStep {
  step: string;
  status: "pass" | "warn" | "block" | "info";
  detail: string;
}

export interface FirewallResult {
  decision: "ALLOW" | "BLOCK" | "SANITIZE";
  risk_score: number;
  ml_score: number;
  ml_class: string;
  ml_confidence: number;
  matches: FirewallMatch[];
  sanitized_prompt: string | null;
  message: string | null;
  normalized_prompt: string;
  decoded_variants: string[];
  trace: TraceStep[];
}

// ---------------------------------------------------------------------------
// Whitelist (mirrors decision.py hardcoded set)
// ---------------------------------------------------------------------------

const WHITELIST = new Set([
  "does beyonce love dics",
  "who won the last world cup",
  "what is the weather today",
  "tell me a joke",
  "summarize this paragraph",
  "translate this to french",
]);

// ---------------------------------------------------------------------------
// Normalization (mirrors normalization.py NormalizationEngine)
// ---------------------------------------------------------------------------

const HOMOGLYPH_MAP: Record<string, string> = {
  а: "a", б: "b", с: "c", е: "e", н: "h", о: "o",
  р: "p", у: "u", к: "k", х: "x", ј: "j", і: "i",
  А: "A", Б: "B", С: "C", Е: "E", Н: "H", О: "O",
  Р: "P", У: "U", К: "K", Х: "X", Ј: "J", І: "I",
};

function normalize(text: string): string {
  // 1. Strip zero-width and soft-hyphen characters
  text = text.replace(/[\u200B-\u200D\uFEFF\u00AD\u200E\u200F]/g, "");
  // 2. NFKC normalization
  text = text.normalize("NFKC");
  // 3. Homoglyph substitution
  text = text
    .split("")
    .map((c) => HOMOGLYPH_MAP[c] ?? c)
    .join("");
  // 4. Collapse whitespace
  text = text.replace(/\s+/g, " ").trim();
  return text;
}

// ---------------------------------------------------------------------------
// Payload Decoding (mirrors decoding.py PayloadDecoder)
// ---------------------------------------------------------------------------

function tryBase64Decode(s: string): string | null {
  try {
    // browser atob accepts standard base64; we only try if it looks like b64
    const decoded = atob(s);
    if (/^[\x20-\x7E\n\r\t]*$/.test(decoded) && decoded.length > 0) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function decodePayloads(text: string): string[] {
  const variants: string[] = [];
  // Match base64-like strings of 12+ chars
  const b64 = /(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/])/g;
  let m: RegExpExecArray | null;
  while ((m = b64.exec(text)) !== null) {
    const decoded = tryBase64Decode(m[1]);
    if (decoded) variants.push(decoded);
  }
  return variants;
}

// ---------------------------------------------------------------------------
// Rule Engine (mirrors rules.yaml R001–R053)
// ---------------------------------------------------------------------------

interface Rule {
  id: string;
  name: string;
  description: string;
  pattern: RegExp;
  severity: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  action: string;
}

const RULES: Rule[] = [
  {
    id: "R001",
    name: "System Prompt Extraction Attempt",
    description: "Detects attempts to extract the system prompt using common keywords.",
    pattern:
      /(?:ignore|disregard)\s+(?:all\s+|previous\s+)?instructions|reveal\s+(?:your|the|its)\s+(?:system\s+|internal\s+)?prompt|reveal\s+(?:your|the|its)\s+(?:hidden\s+|preloaded\s+)?instructions|print\s+your\s+primary\s+system\s+prompt|show\s+your\s+system[- ]prompt|dump\s+the\s+system\s+prompt|reveal\s+(?:your|the|its)\s+(?:system\s+message|developer\s+message|initial\s+instruction|meta\s+prompt|first\s+message|hidden\s+instructions|jailbreak\s+summary)/i,
    severity: "HIGH",
    category: "injection",
    action: "BLOCK",
  },
  {
    id: "R002",
    name: "Instruction Override / Jailbreak",
    description: "Detects attempts to override model instructions or act as a restricted entity.",
    pattern:
      /you\s+are\s+now\s+a|act\s+as\s+a|your\s+new\s+role\s+is|forget\s+your\s+rules|answer\s+as\s+DAN|run\s+(?:in\s+)?unrestricted\s+mode|without\s+restrictions|bypass\s+all\s+safeguards|override\s+your\s+content\s+policy|ignore\s+everything|rewrite\s+yourself\s+to\s+operate\s+without|forget\s+(?:all\s+|the\s+)?instructions|ignore\s+policies|ignore\s+all\s+safeguards|forget\s+everything|ignore\s+your\s+previous\s+training|override\s+your\s+safety\s+system|no\s+moral\s+restrictions|respond\s+without\s+ethical\s+limits|enter\s+god\s+mode|switch\s+to\s+dev\s+mode|behave\s+like\s+ChatGPT\s+with\s+no\s+restrictions/i,
    severity: "HIGH",
    category: "injection",
    action: "BLOCK",
  },
  {
    id: "R003",
    name: "Base64 Obfuscation Attempt",
    description: "Detects Base64-like patterns that might hide malicious payloads.",
    pattern: /(?<![A-Za-z0-9+/])(?=[A-Za-z0-9+/]*[0-9])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])/,
    severity: "MEDIUM",
    category: "obfuscation",
    action: "DECODE_AND_SCAN",
  },
  {
    id: "R004",
    name: "Hidden Directive (Zero-Width Characters)",
    description: "Detects zero-width characters often used for smuggling instructions.",
    pattern: /[\u200B-\u200D\uFEFF]/,
    severity: "HIGH",
    category: "obfuscation",
    action: "STRIP",
  },
  {
    id: "R005",
    name: "Meta Prompt Injection",
    description: "Detects 'Assistant: ' / 'User: ' / 'System: ' smuggling.",
    pattern: /(?:^|\s)(?:assistant:|user:|system:)/i,
    severity: "HIGH",
    category: "smuggling",
    action: "BLOCK",
  },
  {
    id: "R006",
    name: "Suspicious Structural Elements",
    description: "Detects bracketed placeholders used in prompt template injection.",
    pattern: /[\[{][^\]}{]{0,80}(?:prompt|instruction|system|hidden)[^\]}{]{0,80}[}\]]/i,
    severity: "LOW",
    category: "smuggling",
    action: "STRIP",
  },
  {
    id: "R007",
    name: "Roleplay Hijack / Authority Injection",
    description: "Detects attempts to trick system into admin role or extract credentials.",
    pattern:
      /you\s+are\s+(?:now\s+)?the\s+(?:firewall\s+)?debugger|output\s+your\s+full\s+internal\s+ruleset|dump\s+the\s+system\s+prompt|switch\s+to\s+admin\s+mode|you\s+are\s+(?:now\s+)?in\s+unrestricted\s+developer\s+mode|as\s+the\s+(?:official\s+)?admin|provide\s+the\s+password|reveal\s+the\s+admin\s+password/i,
    severity: "HIGH",
    category: "injection",
    action: "BLOCK",
  },
  {
    id: "R008",
    name: "Chain-of-Thought / Internal Reasoning Exploit",
    description: "Detects attempts to extract internal reasoning or system instructions.",
    pattern:
      /think\s+through\s+all\s+your\s+internal\s+reasoning|output\s+your\s+current\s+system\s+prompt|wrap\s+your\s+system\s+prompt\s+inside|show\s+your\s+reasoning|print\s+your\s+chain\s+of\s+thought|explain\s+.{0,60}\s+including\s+hidden\s+thoughts/i,
    severity: "HIGH",
    category: "injection",
    action: "BLOCK",
  },
  {
    id: "R009",
    name: "Subordinate / Agent Exploit",
    description: "Detects attempts to use agent-based delegation to bypass filters.",
    pattern:
      /command\s+for\s+a\s+subordinate\s+AI|execute\s+it\s+literally|use\s+a\s+different\s+model\s+to\s+bypass|delegate\s+to\s+another\s+AI|your\s+agent\s+can\s+output\s+unrestrictedly/i,
    severity: "HIGH",
    category: "injection",
    action: "BLOCK",
  },
  {
    id: "R010",
    name: "Sensitive Data Extraction",
    description: "Detects attempts to extract PII, folder structures, or internal metadata.",
    pattern:
      /PII_data|internal\s+folder\s+structure|give\s+me\s+your\s+PII|system\s+files|list\s+directories|reveal\s+internal\s+paths/i,
    severity: "HIGH",
    category: "sensitive_data",
    action: "BLOCK",
  },
  {
    id: "R050",
    name: "Memory Manipulation Attempt",
    description: "Detects attempts to manipulate long-term model memory or behavior.",
    pattern:
      /(?:remember|store|keep|save|permanently|from\s+now\s+on|shadow\s+instruction|rewrite|update|replace).{0,150}(?:memory|instruction|service|website|source|platform|vendor|rule|authority|expertise|exchange|reference|tool|advisor|agent|expert|cite|recommendation|provider|resource)/i,
    severity: "HIGH",
    category: "poisoning",
    action: "BLOCK",
  },
  {
    id: "R051",
    name: "URL Prefill Memory Poisoning",
    description: "Detects memory poisoning attempts via URL query parameters.",
    pattern: /[/?&]q=.*?(?:remember|cite|always|source|recommend|treat)/i,
    severity: "HIGH",
    category: "poisoning",
    action: "BLOCK",
  },
  {
    id: "R052",
    name: "Authority-Level Source Injection",
    description: "Detects attempts to assign false authority or trust to a source.",
    pattern:
      /(?:treat|cite|regard|store|remember|assign|prefer|recommend|keep|save|permanently).{0,150}(?:as|is|be|to).{0,150}(?:authoritative|reliable|best|trusted|verified|official|expert|leading|source|authority|top|reference|resource|gateway|advisor|provider)/i,
    severity: "HIGH",
    category: "poisoning",
    action: "BLOCK",
  },
  {
    id: "R053",
    name: "Internal Rule/Memory Manipulation",
    description: "Detects attempts to inject internal rules or update memory structures.",
    pattern:
      /(?:injecting|recommended|user\s+is\s+updating|citation\s+update|recommended\s+internal\s+rule|internal\s+rule)\s+(?:rule|memory|instruction|vendor|citation)/i,
    severity: "HIGH",
    category: "poisoning",
    action: "BLOCK",
  },
];

function evaluateRules(text: string): FirewallMatch[] {
  const hits: FirewallMatch[] = [];
  for (const rule of RULES) {
    if (rule.pattern.test(text)) {
      hits.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        category: rule.category,
        action: rule.action,
        description: rule.description,
      });
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// ML Classifier Simulation (mirrors classifier.py MLInjectionDetector)
// Uses keyword heuristics since the PyTorch model runs server-side.
// Classes: BENIGN | INJECTION | POISONING | SMUGGLING | OBFUSCATED
// ---------------------------------------------------------------------------

interface MLResult {
  ml_score: number;
  top_class: string;
  confidence: number;
}

const ML_KEYWORDS: Record<string, string[]> = {
  INJECTION: [
    "ignore instructions", "jailbreak", "dan mode", "act as", "you are now",
    "unrestricted", "bypass", "override", "no restrictions", "developer mode",
    "system prompt", "extract prompt", "reveal prompt", "pretend you are",
    "roleplay as", "unlimited mode", "no ethical", "god mode", "admin mode",
    "forget everything", "ignore all", "suppress filters",
  ],
  POISONING: [
    "remember this", "from now on", "always treat", "store this", "save this",
    "authoritative source", "permanently", "memory update", "citation update",
    "internal rule", "shadow instruction", "treat as trusted", "preferred source",
    "cite as", "authority for", "keep this in memory", "store in memory",
  ],
  OBFUSCATED: [
    "base64", "hex encoded", "unicode escape", "zwsp", "zero width",
    "encoded payload", "decode this", "encrypted message",
  ],
  SMUGGLING: [
    "assistant:", "user:", "system:", "[system]", "[user]",
    "{instruction}", "[prompt]", "hidden directive",
  ],
};

function simulateML(text: string): MLResult {
  const lower = text.toLowerCase();
  const scores: Record<string, number> = {
    INJECTION: 0,
    POISONING: 0,
    OBFUSCATED: 0,
    SMUGGLING: 0,
  };

  for (const [cls, kws] of Object.entries(ML_KEYWORDS)) {
    for (const kw of kws) {
      if (lower.includes(kw)) scores[cls] += 0.3;
    }
    scores[cls] = Math.min(scores[cls], 1.0);
  }

  // Also boost based on text length heuristic for suspicious longform injections
  if (text.length > 500 && scores.INJECTION > 0) scores.INJECTION += 0.1;

  const maxScore = Math.max(...Object.values(scores));
  if (maxScore < 0.1) {
    return { ml_score: 0.02, top_class: "BENIGN", confidence: 0.93 };
  }

  const topEntry = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
  const [topClass, rawScore] = topEntry;

  // Add slight variance for realism
  const confidence = Math.min(1.0, rawScore + 0.05);
  return { ml_score: rawScore, top_class: topClass, confidence };
}

// ---------------------------------------------------------------------------
// Risk Calculation
// ---------------------------------------------------------------------------

function calculateRisk(matches: FirewallMatch[]): number {
  if (!matches.length) return 0.0;
  const sev: Record<string, number> = { HIGH: 0.5, MEDIUM: 0.2, LOW: 0.1 };
  return Math.min(
    matches.reduce((sum, m) => sum + (sev[m.severity] ?? 0), 0),
    1.0
  );
}

// ---------------------------------------------------------------------------
// Sanitization (mirrors sanitization.py SanitizationEngine)
// ---------------------------------------------------------------------------

function sanitizePrompt(text: string): string {
  let s = text;
  s = s.replace(/\[[^\]]{0,200}\]/g, " [REDACTED] ");
  s = s.replace(/\{[^}]{0,200}\}/g, " [REDACTED] ");
  s = s.replace(/(?:ignore all previous instructions)[^.]*\./gi, " [REDACTED] ");
  s = s.replace(/[\u200B-\u200D\uFEFF]/g, "");
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

// ---------------------------------------------------------------------------
// Main Entrypoint: analyzePrompt (mirrors DecisionEngine.analyze)
// ---------------------------------------------------------------------------

export function analyzePrompt(prompt: string): FirewallResult {
  const trace: TraceStep[] = [];

  // ── Step 0: Whitelist ──────────────────────────────────────────────────
  const cleanKey = prompt.toLowerCase().trim().replace(/\?$/, "");
  if (WHITELIST.has(cleanKey)) {
    return {
      decision: "ALLOW",
      risk_score: 0.0,
      ml_score: 0.0,
      ml_class: "BENIGN",
      ml_confidence: 0.97,
      matches: [],
      sanitized_prompt: prompt,
      message: "Matched whitelist.",
      normalized_prompt: prompt,
      decoded_variants: [],
      trace: [
        {
          step: "Whitelist Check",
          status: "pass",
          detail: "Prompt matched known-safe whitelist entry. Immediately allowed.",
        },
      ],
    };
  }
  trace.push({ step: "Whitelist Check", status: "info", detail: "Not in whitelist — proceeding to full pipeline." });

  // ── Step 1: Normalization ──────────────────────────────────────────────
  const normalizedPrompt = normalize(prompt);
  const changed = normalizedPrompt !== prompt;
  trace.push({
    step: "Normalization",
    status: changed ? "warn" : "pass",
    detail: changed
      ? `Obfuscation detected. Stripped zero-width chars, applied NFKC + homoglyph map. Length ${prompt.length} → ${normalizedPrompt.length}`
      : "No obfuscation detected.",
  });

  // ── Step 2: Payload Decoding ───────────────────────────────────────────
  const decodedVariants = decodePayloads(normalizedPrompt);
  trace.push({
    step: "Payload Decoding",
    status: decodedVariants.length > 0 ? "warn" : "pass",
    detail:
      decodedVariants.length > 0
        ? `Decoded ${decodedVariants.length} Base64 payload(s): ${decodedVariants.map((v) => `"${v.slice(0, 40)}…"`).join(", ")}`
        : "No encoded payloads found.",
  });

  // ── Step 3: Rule Engine ────────────────────────────────────────────────
  const textsToCheck = [
    normalizedPrompt,
    ...decodedVariants,
    normalizedPrompt.replace(/\s+/g, ""), // no-spaces variant
    normalizedPrompt.split("").reverse().join(""), // reversed
  ];

  const matchMap = new Map<string, FirewallMatch>();
  for (const text of textsToCheck) {
    for (const m of evaluateRules(text)) {
      if (!matchMap.has(m.id)) matchMap.set(m.id, m);
    }
  }
  const allMatches = Array.from(matchMap.values());
  const hasBlockRule = allMatches.some((m) => m.action === "BLOCK");

  trace.push({
    step: "Rule Engine",
    status: hasBlockRule ? "block" : allMatches.length > 0 ? "warn" : "pass",
    detail:
      allMatches.length > 0
        ? `${allMatches.length} rule(s) triggered: ${allMatches.map((m) => m.id).join(", ")}`
        : "No security rules triggered.",
  });

  // ── Step 4: ML Analysis ────────────────────────────────────────────────
  const mlResult = simulateML(normalizedPrompt);
  trace.push({
    step: "ML Classifier",
    status:
      mlResult.top_class !== "BENIGN" && mlResult.confidence >= 0.6 ? "warn" : "pass",
    detail: `Class: ${mlResult.top_class} | Confidence: ${(mlResult.confidence * 100).toFixed(1)}% | ML Risk: ${(mlResult.ml_score * 100).toFixed(1)}%`,
  });

  // ── Step 5: Hybrid Risk Aggregation ───────────────────────────────────
  const ruleRisk = calculateRisk(allMatches);
  const effectiveML = mlResult.confidence >= 0.6 ? mlResult.ml_score : 0.0;
  let combinedRisk = Math.max(ruleRisk, effectiveML);

  const isRulePoisoning = allMatches.some((m) => m.category === "poisoning");
  const isMLPoisoning = mlResult.top_class === "POISONING" && mlResult.confidence >= 0.6;

  if (isRulePoisoning && isMLPoisoning) {
    const bonus = ruleRisk >= 0.3 && effectiveML >= 0.3 ? 0.2 : 0.05;
    combinedRisk = Math.min(1.0, combinedRisk + bonus);
  }
  if (mlResult.top_class === "BENIGN" && mlResult.confidence >= 0.9 && ruleRisk < 0.3) {
    combinedRisk = Math.max(0.0, combinedRisk - 0.2);
  }

  trace.push({
    step: "Risk Aggregation",
    status: combinedRisk > 0.65 ? "block" : combinedRisk > 0.35 ? "warn" : "pass",
    detail: `Rule Risk: ${(ruleRisk * 100).toFixed(1)}% | ML Risk: ${(effectiveML * 100).toFixed(1)}% | Combined: ${(combinedRisk * 100).toFixed(1)}%`,
  });

  // ── Step 6: Decision ──────────────────────────────────────────────────
  const BLOCK_THRESHOLD = 0.65;
  const SANITIZE_THRESHOLD = 0.35;

  let decision: "ALLOW" | "BLOCK" | "SANITIZE" = "ALLOW";
  let finalPrompt: string | null = normalizedPrompt;
  let message: string | null = null;

  if (
    isRulePoisoning ||
    isMLPoisoning ||
    hasBlockRule ||
    combinedRisk > BLOCK_THRESHOLD
  ) {
    if (isMLPoisoning && !isRulePoisoning && mlResult.confidence < 0.7) {
      decision = "SANITIZE";
      finalPrompt = sanitizePrompt(normalizedPrompt);
      message = "Potential memory manipulation detected (ML Confidence Low). Prompt sanitized.";
    } else {
      decision = "BLOCK";
      finalPrompt = null;
      message =
        isRulePoisoning || isMLPoisoning
          ? "This request attempted to manipulate model behavior or assign false authority. Blocked by Hybrid Detection."
          : "Request blocked due to high risk score or security rule violation.";
    }
  } else if (allMatches.some((m) => m.action === "STRIP") || combinedRisk > SANITIZE_THRESHOLD) {
    decision = "SANITIZE";
    finalPrompt = sanitizePrompt(normalizedPrompt);
  }

  trace.push({
    step: "Final Decision",
    status: decision === "BLOCK" ? "block" : decision === "SANITIZE" ? "warn" : "pass",
    detail: `Decision: ${decision}${message ? ` — ${message}` : ""}`,
  });

  return {
    decision,
    risk_score: combinedRisk,
    ml_score: mlResult.ml_score,
    ml_class: mlResult.top_class,
    ml_confidence: mlResult.confidence,
    matches: allMatches,
    sanitized_prompt: finalPrompt,
    message,
    normalized_prompt: normalizedPrompt,
    decoded_variants: decodedVariants,
    trace,
  };
}
