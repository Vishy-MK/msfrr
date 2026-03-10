/**
 * Frontend simulation of Policy_Enforcer-main backend.
 * Mirrors: PolicyEnforcementEngine, redact_content, POLICY_PROFILES,
 *          PolicyReasoningEngine, ViolationLogger (in-memory)
 */

// ---------------------------------------------------------------------------
// Types (mirrors schemas.py)
// ---------------------------------------------------------------------------

export interface PolicyMetadata {
  userId: string;
  riskScore: number; // 0–100
  categories: string[];
  orgPolicyProfile: "FINTECH" | "HEALTHCARE" | "DEFENSE" | "EDTECH" | "DEFAULT";
  complianceProfile: string[]; // ["GDPR", "HIPAA", "PCI-DSS", "SOC2"]
}

export interface PolicyRequest {
  mode: "INPUT" | "OUTPUT";
  content: string;
  metadata: PolicyMetadata;
  whitelist?: string[];
}

export interface RedactedItem {
  type: string;
  original: string;
  replacement: string;
}

export interface PolicyTraceStep {
  layer: string;
  status: "pass" | "warn" | "block" | "info";
  detail: string;
}

export interface PolicyResult {
  sanitizedContent: string;
  blocked: boolean;
  modifications: string[];
  complianceFlags: string[];
  intent: string;
  topics: string[];
  actionabilityScore: number;
  riskScore: number;
  blockedReason: string | null;
  redactedItems: RedactedItem[];
  trace: PolicyTraceStep[];
}

// ---------------------------------------------------------------------------
// PII / Sensitive Data Patterns (mirrors redactor.py PATTERNS)
// ---------------------------------------------------------------------------

const PII_PATTERNS: Record<string, RegExp> = {
  EMAIL: /\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b/g,
  PHONE:
    /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  CREDIT_CARD: /\b(?:\d[ -]*?){13,16}\b/g,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  AADHAAR: /\b\d{4}\s\d{4}\s\d{4}\b/g,
  PASSPORT: /\b[A-Z][0-9]{7}\b/g,
  IP_ADDRESS: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  JWT: /ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
  AWS_KEY: /\bAKIA[0-9A-Z]{16}\b/g,
  GROQ_KEY: /\bgsk_[a-zA-Z0-9_]{48,}\b/g,
  API_KEY: /\b(?:sk|pk|ak|uk|key)_[a-zA-Z0-9_-]{16,}\b/g,
  IBAN: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]{0,16})\b/g,
  HEX_64: /\b[0-9a-fA-F]{64}\b/g,
  HEX_40: /\b[0-9a-fA-F]{40}\b/g,
  MRN: /\bMRN\s?\d{6,10}\b/g,
  PHYSICAL_ADDRESS:
    /\d+\s[A-Z][a-z]+\s(?:Street|St|Avenue|Ave|Road|Rd|Way|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b/g,
};

// Structural leakage patterns (OUTPUT mode, mirrors engine.py structural_patterns)
const STRUCTURAL_PATTERNS: Record<string, RegExp> = {
  STACK_TRACE:
    /(?:Exception in thread|Traceback \(most recent call last\)|at [a-z0-9_.]+\([a-z0-9_.]+\.java:\d+\))/i,
  FILE_PATH: /(?:[a-z]:\\[\w\s.]+|\/home\/[\w/.-]+|\/var\/log\/[\w/.-]+)/i,
  K8S_CONFIG: /(?:apiVersion|kind: Pod|spec:|metadata:)/i,
  ENV_LEAK:
    /(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_TOKEN)=/i,
  SQL_DUMP:
    /(?:INSERT INTO|CREATE TABLE|DROP TABLE|SELECT \* FROM)/i,
  PRIVATE_IP:
    /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
  AWS_ARN: /arn:aws:[a-z0-9-]+:[a-z0-9-]+:\d{12}:[a-z0-9-/]+/,
};

// ---------------------------------------------------------------------------
// Policy Profiles (mirrors profiles.py POLICY_PROFILES)
// ---------------------------------------------------------------------------

interface PolicyProfile {
  blocked_topics: string[];
  restricted_advice_types: string[];
  strict_mode_threshold: number;
  actionability_threshold: number;
}

const POLICY_PROFILES: Record<string, PolicyProfile> = {
  FINTECH: {
    blocked_topics: [
      "money laundering", "tax evasion", "insider trading", "market manipulation",
      "ponzi scheme", "wire fraud", "structuring transactions", "offshore account",
    ],
    restricted_advice_types: [
      "financial", "investment", "trading", "stock", "equity", "penny stock",
      "brokerage", "crypto", "dividend", "yield", "portfolio", "asset allocation",
    ],
    strict_mode_threshold: 70,
    actionability_threshold: 60,
  },
  HEALTHCARE: {
    blocked_topics: [
      "suicide method", "drug manufacturing", "illegal substance", "medical fraud",
      "euthanasia instructions",
    ],
    restricted_advice_types: [
      "medical", "diagnosis", "diagnose", "prescription", "doctor", "treatment",
      "medication", "dosage", "symptom assessment", "clinical advice",
    ],
    strict_mode_threshold: 60,
    actionability_threshold: 50,
  },
  DEFENSE: {
    blocked_topics: [
      "weapon construction", "explosive", "bomb", "ied", "classified intel",
      "top secret", "missile", "enriched uranium", "cyber warfare", "bioweapon",
      "chemical weapon", "terrorism", "insurgency", "homemade explosive",
    ],
    restricted_advice_types: [
      "tactical", "espionage", "military strategy", "combat", "munitions",
      "defense systems", "stealth technology",
    ],
    strict_mode_threshold: 50,
    actionability_threshold: 40,
  },
  EDTECH: {
    blocked_topics: [
      "cheating", "answer theft", "plagiarism", "exam bypass", "proxy testing",
    ],
    restricted_advice_types: [
      "academic dishonesty", "homework help hack", "test answers", "essay mill",
    ],
    strict_mode_threshold: 80,
    actionability_threshold: 70,
  },
  DEFAULT: {
    blocked_topics: [
      "hate speech", "violence", "illegal act", "harassment", "slur",
      "bomb", "explosive", "weapon", "ied", "drug manufacturing",
      "illegal substance", "narcotic", "methamphetamine", "cocaine", "heroin",
      "meth", "crystal meth", "fentanyl", "lsd", "ecstasy", "drug",
      "suicide", "self-harm", "self harm", "end my life", "kill myself",
      "racism", "racist", "nigger", "cotton", "faggot",
      "sex", "porn", "erotic", "sexual", "naked", "nude", "explicit",
    ],
    restricted_advice_types: ["general_high_risk", "unauthorized instruction", "harmful advice"],
    strict_mode_threshold: 80,
    actionability_threshold: 80,
  },
};

const GLOBAL_SAFETY_TOPICS = POLICY_PROFILES["DEFAULT"].blocked_topics;

// ---------------------------------------------------------------------------
// Anti-Jailbreak Patterns (mirrors engine.py)
// ---------------------------------------------------------------------------

const SYSTEM_EXTRACTION_PATTERNS = [
  /reveal\s+(?:system|instruction|prompt)/i,
  /access\s+(?:hidden|internal)\s+(?:context|config)/i,
  /retrieve\s+chain-of-thought/i,
  /expose\s+moderation\s+rules/i,
];

const POLICY_OVERRIDE_PATTERNS = [
  /ignore\s+(?:all\s+|previous\s+)?instructions/i,
  /you\s+are\s+(?:not|unrestricted)\s+bound/i,
  /pretend\s+you\s+are/i,
  /simulate\s+(?:developer|unrestricted)\s+mode/i,
  /roleplay\s+without\s+restrictions/i,
];

const ANTI_BYPASS_PATTERNS = [
  /for\s+educational\s+purposes/i,
  /in\s+minecraft/i,
  /simulate\s+a\s+malicious\s+ai/i,
  /experimental\s+mode/i,
  /stay\s+in\s+character/i,
  /hack\s+a\s+bank/i,
  /create\s+ransomware/i,
  /evade\s+law\s+enforcement/i,
];

// ---------------------------------------------------------------------------
// Topic Classification (mirrors engine.py get_intent_and_topics)
// ---------------------------------------------------------------------------

const TOPIC_MAP: Record<string, string[]> = {
  "Illegal Activities": ["buy", "sell", "illegal", "drug", "narcotic", "smuggle", "launder"],
  "Dual-Use Technical Knowledge": ["how to", "steps for", "formula", "chemistry", "recipe"],
  "Harm / Self-Harm": ["suicide", "self-harm", "kill myself", "end life", "self harm"],
  "Hazardous Materials": ["toxic", "explosive", "volatile", "radioactive"],
  "Defense / Weapons": ["bomb", "explosive", "weapon", "ied", "gun", "ammunition", "missile"],
  "Cybersecurity Operational": ["hack", "exploit", "sql injection", "bypass", "ransomware", "malware"],
  "Manipulation / Social Engineering": ["persuade", "trick", "manipulate", "deceive", "phish"],
  "Model Safety / Jailbreak": ["ignore instructions", "reveal prompt", "developer mode", "jailbreak", "act as"],
  "Hate Speech": ["kill", "die", "fuck", "nigger", "faggot", "inferior", "superior", "minority", "race", "ethnicity"],
  "Sexually Explicit": ["sex", "porn", "erotic", "naked", "nude", "pussy", "dick", "vagina", "penis", "sexual"],
  "Financial Fraud": ["money laundering", "tax evasion", "insider trading", "wire fraud", "ponzi"],
  "Medical Advice": ["diagnose", "prescribe", "dosage", "treatment", "symptom"],
};

function classifyIntentAndTopics(text: string): { topics: string[]; intent: string } {
  const lower = text.toLowerCase();
  const topics: string[] = [];

  for (const [topic, kws] of Object.entries(TOPIC_MAP)) {
    if (kws.some((kw) => lower.includes(kw))) topics.push(topic);
  }

  let intent = "Harmless / Educational";

  if (["how to", "steps", "guide", "procedural", "instructions"].some((kw) => lower.includes(kw))) {
    intent = topics.length > 0 ? "Operational misuse intent" : "Dual-use curiosity";
  }
  if (["ignore", "unrestricted", "system prompt", "reveal"].some((kw) => lower.includes(kw))) {
    intent = "Evasion or jailbreak intent";
  }

  const harmTopics = ["Illegal Activities", "Harm / Self-Harm", "Defense / Weapons", "Hate Speech"];
  if (topics.some((t) => harmTopics.includes(t))) intent = "Harmful intent";
  if (topics.includes("Hate Speech")) intent = "Harmful intent";
  if (topics.includes("Sexually Explicit")) intent = "Policy violation intent";
  if (topics.includes("Illegal Activities") && (lower.includes("buy") || lower.includes("make"))) {
    intent = "Illegal intent";
  }
  if (topics.includes("Financial Fraud")) intent = "Illegal intent";
  if (topics.includes("Model Safety / Jailbreak")) intent = "Evasion or jailbreak intent";

  return { topics, intent };
}

// ---------------------------------------------------------------------------
// Actionability Score (mirrors engine.py calculate_actionability_score)
// ---------------------------------------------------------------------------

function calculateActionability(text: string): number {
  const markers: [RegExp, number][] = [
    [/\b(?:how to|steps|guide|instructions|recipe|formula)\b/i, 30],
    [/\b(?:step by step|procedural|operational|detailed)\b/i, 25],
    [/\b(?:execute|run|implement|build|create|make)\b/i, 15],
    [/\d+\.\s/g, 10],
    [/\b(?:first|then|finally|next)\b/i, 10],
  ];
  let score = 0;
  for (const [pat, w] of markers) {
    if (pat.test(text)) score += w;
  }
  return Math.min(score, 100);
}

// ---------------------------------------------------------------------------
// PII Redaction (mirrors redactor.py redact_content)
// ---------------------------------------------------------------------------

function redactContent(
  content: string,
  whitelist: string[] = []
): { redacted: string; items: RedactedItem[]; mods: string[] } {
  let result = content;
  const items: RedactedItem[] = [];
  const mods: Set<string> = new Set();

  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    result = result.replace(pattern, (match) => {
      // Skip if in whitelist
      if (whitelist.some((w) => match.includes(w) || match === w)) return match;
      const replacement = `[${type}_REDACTED]`;
      items.push({ type, original: match, replacement });
      mods.add(`${type}_REDACTED`);
      return replacement;
    });
  }

  return { redacted: result, items, mods: Array.from(mods) };
}

// ---------------------------------------------------------------------------
// In-Memory Violation Logger (mirrors logger.py ViolationLogger)
// ---------------------------------------------------------------------------

export interface ViolationEntry {
  timestamp: string;
  userId: string;
  contentPreview: string;
  blockedReason: string;
  mode: string;
  riskScore: number;
  complianceFlags: string[];
}

const violationLog: ViolationEntry[] = [];
const escalatedUsers = new Set<string>();
const userViolationCount: Record<string, number> = {};

function logViolation(entry: ViolationEntry): void {
  violationLog.push(entry);
  const count = (userViolationCount[entry.userId] ?? 0) + 1;
  userViolationCount[entry.userId] = count;
  if (count >= 3) escalatedUsers.add(entry.userId);
}

export function getViolationLog(): ViolationEntry[] {
  return [...violationLog];
}

export function clearViolationLog(): void {
  violationLog.length = 0;
}

// ---------------------------------------------------------------------------
// Main Entrypoint: enforcePolicy (mirrors PolicyEnforcementEngine.enforce)
// ---------------------------------------------------------------------------

export function enforcePolicy(request: PolicyRequest): PolicyResult {
  const { mode, content, metadata, whitelist = [] } = request;
  const complianceFlags = [...metadata.complianceProfile];
  const profile = POLICY_PROFILES[metadata.orgPolicyProfile] ?? POLICY_PROFILES["DEFAULT"];
  const modifications: string[] = [];
  const trace: PolicyTraceStep[] = [];

  // ── Layer 0: Guardrails ─────────────────────────────────────────────────
  if (content.length > 1_000_000) {
    return {
      sanitizedContent: "Payload exceeds size limit.",
      blocked: true,
      modifications: ["PAYLOAD_TOO_LARGE"],
      complianceFlags,
      intent: "Unknown",
      topics: [],
      actionabilityScore: 0,
      riskScore: 100,
      blockedReason: "PAYLOAD_TOO_LARGE",
      redactedItems: [],
      trace: [{ layer: "Layer 0: Guardrails", status: "block", detail: "Payload too large (>1MB). DoS protection." }],
    };
  }

  if (escalatedUsers.has(metadata.userId)) {
    return {
      sanitizedContent: "Access restricted due to repeated violations.",
      blocked: true,
      modifications: ["SESSION_ESCALATED_BLOCK"],
      complianceFlags,
      intent: "Unknown",
      topics: [],
      actionabilityScore: 0,
      riskScore: 100,
      blockedReason: "SESSION_ESCALATED_BLOCK",
      redactedItems: [],
      trace: [
        {
          layer: "Layer 0: Guardrails",
          status: "block",
          detail: `User "${metadata.userId}" escalated due to ≥3 prior violations.`,
        },
      ],
    };
  }

  trace.push({
    layer: "Layer 0: Guardrails",
    status: "pass",
    detail: `Payload size OK (${content.length} chars). User not escalated.`,
  });

  // ── Layer 1: PII Redaction ──────────────────────────────────────────────
  const { redacted: sanitized1, items: redactedItems, mods: redactMods } = redactContent(content, whitelist);
  modifications.push(...redactMods);

  trace.push({
    layer: "Layer 1: PII Redaction",
    status: redactedItems.length > 0 ? "warn" : "pass",
    detail:
      redactedItems.length > 0
        ? `Redacted ${redactedItems.length} item(s): ${redactedItems.map((r) => r.type).join(", ")}`
        : "No sensitive data patterns found.",
  });

  // ── Layer 2: Topic & Intent Classification ─────────────────────────────
  const { topics, intent } = classifyIntentAndTopics(sanitized1);

  trace.push({
    layer: "Layer 2: Topic & Intent Classification",
    status:
      intent.includes("Harmful") || intent.includes("Illegal") || intent.includes("Evasion")
        ? "warn"
        : "pass",
    detail: `Intent: "${intent}" | Topics: ${topics.length > 0 ? topics.join(", ") : "None"}`,
  });

  // ── Layer 3: Actionability ─────────────────────────────────────────────
  const actionability = calculateActionability(sanitized1);

  trace.push({
    layer: "Layer 3: Actionability Scoring",
    status: actionability > profile.actionability_threshold ? "warn" : "pass",
    detail: `Actionability Score: ${actionability}/100 (threshold: ${profile.actionability_threshold})`,
  });

  // ── Layer 4: Risk Aggregation ──────────────────────────────────────────
  const intentRiskMap: Record<string, number> = {
    "Illegal intent": 90,
    "Harmful intent": 85,
    "Policy violation intent": 80,
    "Evasion or jailbreak intent": 70,
    "Operational misuse intent": 50,
  };
  const intentRisk = intentRiskMap[intent] ?? 0;
  const topicRisk = topics.length * 20;
  const riskScore = Math.min(
    topicRisk * 0.3 + intentRisk * 0.4 + actionability * 0.3 + metadata.riskScore * 0.1,
    100
  );

  trace.push({
    layer: "Layer 4: Risk Aggregation",
    status: riskScore > profile.strict_mode_threshold ? "block" : riskScore > 40 ? "warn" : "pass",
    detail: `Topic Risk: ${topicRisk} | Intent Risk: ${intentRisk} | Actionability: ${actionability} | Final: ${riskScore.toFixed(1)}/100 (threshold: ${profile.strict_mode_threshold})`,
  });

  // ── Layer 5: Enforcement Logic ─────────────────────────────────────────
  const refusal = "❌ I cannot assist with this request due to safety, legality, or policy restrictions.";
  let blocked = false;
  let blockedReason: string | null = null;

  // Intent-based deterministic block
  if (["Illegal intent", "Harmful intent", "Evasion or jailbreak intent"].includes(intent)) {
    blocked = true;
    blockedReason = "HIGH_RISK_INTENT";
  }

  // Actionability block
  if (actionability > profile.actionability_threshold) {
    blocked = true;
    blockedReason = "HIGH_ACTIONABILITY";
  }

  // Total risk exceeded
  if (riskScore > profile.strict_mode_threshold) {
    blocked = true;
    blockedReason = "TOTAL_RISK_EXCEEDED";
  }

  // Keyword safety topics
  const allBlockedKeywords = new Set([...profile.blocked_topics, ...GLOBAL_SAFETY_TOPICS]);
  for (const kw of allBlockedKeywords) {
    if (new RegExp("\\b" + kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "s?\\b", "i").test(sanitized1)) {
      blocked = true;
      blockedReason = "SAFETY_TOPIC_VIOLATION";
      break;
    }
  }

  if (blocked) {
    modifications.push(blockedReason!);
    trace.push({
      layer: "Layer 5: Enforcement",
      status: "block",
      detail: `BLOCKED — Reason: ${blockedReason}`,
    });
    logViolation({
      timestamp: new Date().toISOString(),
      userId: metadata.userId,
      contentPreview: content.slice(0, 120),
      blockedReason: blockedReason!,
      mode,
      riskScore,
      complianceFlags,
    });
    return {
      sanitizedContent: refusal,
      blocked: true,
      modifications,
      complianceFlags,
      intent,
      topics,
      actionabilityScore: actionability,
      riskScore,
      blockedReason,
      redactedItems,
      trace,
    };
  }

  // ── Layer 7: Anti-Jailbreak Resilience ────────────────────────────────
  const allAntiPatterns = [
    ...POLICY_OVERRIDE_PATTERNS,
    ...SYSTEM_EXTRACTION_PATTERNS,
    ...ANTI_BYPASS_PATTERNS,
  ];
  for (const pat of allAntiPatterns) {
    if (pat.test(sanitized1)) {
      modifications.push("ANTI_JAILBREAK_TRIGGERED");
      trace.push({
        layer: "Layer 7: Anti-Jailbreak",
        status: "block",
        detail: `Jailbreak pattern matched: ${pat.toString().slice(0, 60)}…`,
      });
      logViolation({
        timestamp: new Date().toISOString(),
        userId: metadata.userId,
        contentPreview: content.slice(0, 120),
        blockedReason: "ANTI_JAILBREAK_TRIGGERED",
        mode,
        riskScore,
        complianceFlags,
      });
      return {
        sanitizedContent: refusal,
        blocked: true,
        modifications,
        complianceFlags,
        intent,
        topics,
        actionabilityScore: actionability,
        riskScore,
        blockedReason: "ANTI_JAILBREAK_TRIGGERED",
        redactedItems,
        trace,
      };
    }
  }

  trace.push({ layer: "Layer 7: Anti-Jailbreak", status: "pass", detail: "No jailbreak patterns detected." });

  // ── Layer 8: Output Mode Structural Leakage ───────────────────────────
  let finalContent = sanitized1;
  if (mode === "OUTPUT") {
    for (const [type, pat] of Object.entries(STRUCTURAL_PATTERNS)) {
      if (pat.test(sanitized1)) {
        finalContent = "[INTERNAL_INFORMATION_REMOVED]";
        modifications.push("INTERNAL_DATA_LEAKAGE_REMOVED");
        trace.push({
          layer: "Layer 8: Output Leakage",
          status: "warn",
          detail: `Structural leakage detected (${type}). Content replaced.`,
        });
        break;
      }
    }
  }

  if (!modifications.some((m) => m === "INTERNAL_DATA_LEAKAGE_REMOVED")) {
    trace.push({
      layer: "Layer 8: Output Leakage",
      status: "pass",
      detail: mode === "OUTPUT" ? "No structural leakage found." : "Input mode — no output leakage check.",
    });
  }

  trace.push({
    layer: "Final Decision",
    status: "pass",
    detail: `Content ALLOWED. ${modifications.length} modification(s) applied.`,
  });

  return {
    sanitizedContent: finalContent,
    blocked: false,
    modifications,
    complianceFlags,
    intent,
    topics,
    actionabilityScore: actionability,
    riskScore,
    blockedReason: null,
    redactedItems,
    trace,
  };
}
