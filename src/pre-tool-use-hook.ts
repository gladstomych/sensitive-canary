#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  type Message,
  parseAllowTags,
  randomBird,
} from "./lib/inspector.ts";
import { type Finding, scan } from "./lib/rules.ts";

interface HookInput {
  transcript_path?: string;
  tool_name?: string;
  tool_input?: {
    file_path?: string;
    command?: string;
  };
}

interface TranscriptLine {
  message?: Message;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// Maximum bytes to read from the tail of a transcript file.
const MAX_TRANSCRIPT_TAIL_BYTES = 65_536; // 64 KB

// ── Transcript ────────────────────────────────────────────────────────────────

// Returns true when the message contains at least one text content block
// (or is a plain string). Tool-result-only messages are not real user input.
function hasTextContent(msg: Message): boolean {
  if (typeof msg.content === "string") return true;
  return msg.content.some((b) => b.type === "text");
}

// Load allow tags from the Claude Code session transcript.
// Transcript format (JSONL): { "type": "user"|"assistant", "message": { role, content }, … }
// Only the most recent user *text* message is consulted, and only if no tool_result
// entries have been recorded after it. This means allow tags are consumed by the first
// tool call — subsequent tool calls in the same AI turn will be blocked.
function loadAllowTagsFromTranscript(transcriptPath: string): Set<string> {
  let raw: string;
  try {
    const stat = fs.statSync(transcriptPath);
    if (stat.size <= MAX_TRANSCRIPT_TAIL_BYTES) {
      raw = fs.readFileSync(transcriptPath, "utf8");
    } else {
      const buf = Buffer.alloc(MAX_TRANSCRIPT_TAIL_BYTES);
      const fd = fs.openSync(transcriptPath, "r");
      try {
        const bytesRead = fs.readSync(
          fd,
          buf,
          0,
          MAX_TRANSCRIPT_TAIL_BYTES,
          stat.size - MAX_TRANSCRIPT_TAIL_BYTES,
        );
        raw = buf.subarray(0, bytesRead).toString("utf8");
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch {
    return new Set();
  }

  let lastUserMessage: Message | null = null;
  let toolResultAfterLastText = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as TranscriptLine;
      const msg = parsed.message;
      if (msg?.role === "user" && msg.content !== undefined) {
        if (hasTextContent(msg)) {
          lastUserMessage = msg;
          toolResultAfterLastText = false;
        } else {
          toolResultAfterLastText = true;
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  if (!lastUserMessage || toolResultAfterLastText) return new Set();
  return parseAllowTags([lastUserMessage]);
}

// ── Bash helpers ──────────────────────────────────────────────────────────────

const FILE_READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
]);

// LOCAL PATCH: commands whose output lands directly in the conversation and
// whose arguments are the payload. $VAR references are only checked inside
// these segments — `curl -H "x: $TOKEN"` or `API_KEY=$KEY python app.py` is
// legitimate credential *use*; `echo $TOKEN` prints it into context.
const CONTEXT_ECHO_COMMANDS = new Set(["echo", "printf"]);

function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const re = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

  for (const seg of command.split(/\s*[|;&]+\s*/)) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    const cmd = path.basename(tokens[0] ?? "");
    if (!CONTEXT_ECHO_COMMANDS.has(cmd)) continue;
    for (const match of seg.matchAll(re)) {
      const name = match[1] ?? match[2];
      if (name) names.add(name);
    }
  }
  return [...names];
}

function extractFilePathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  const segments = command.split(/\s*[|;&]+\s*/);

  for (const seg of segments) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;

    const cmd = path.basename(tokens[0] ?? "");
    if (!FILE_READ_COMMANDS.has(cmd)) continue;

    let skipNext = false;
    for (let i = 1; i < tokens.length; i++) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      const tok = tokens[i];
      if (!tok) continue;
      if (tok.startsWith("-")) continue;
      if (tok === ">" || tok === ">>" || tok === "<") {
        skipNext = true;
        continue;
      }
      paths.push(tok);
    }
  }

  return [...new Set(paths)];
}

// ── .env pattern ──────────────────────────────────────────────────────────────

// .env and .env.* (e.g. .env.local, .env.production) are blocked unconditionally.
// Files that merely end in .env (e.g. production.env) are handled by content scanning.
// FORK (gladstomych): placeholder files (.env.example and friends) carry no real
// secrets by convention and are how a project documents its config surface, so
// they skip the name block. Content scanning still applies to them.
const ENV_NAME_EXEMPT = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
]);

function isBlockedEnvFile(filePath: string): boolean {
  if (!filePath) return false;
  const base = path.basename(filePath);
  if (ENV_NAME_EXEMPT.has(base)) return false;
  return base === ".env" || base.startsWith(".env.");
}

// FORK (gladstomych): connection strings aimed at the local machine are dev
// plumbing (postgres://postgres:postgres@localhost/db), not leaks. Command
// text only; file contents keep the full rule. The lookahead stops
// localhost.evil.com from passing as local.
const LOCAL_HOST_RE =
  /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?=[:/\s]|$)/;

// Matches the same shape as the connection-string rule, capturing password + host
// so a finding can be tied back to the URL it came from.
const CONNECTION_URL_RE =
  /(?:mongodb|mysql|postgres|postgresql|redis):\/\/[^:\s]+:([^@\s]+)@([^\s/,;'"`)\]}]+)/g;

function isLocalConnectionString(command: string, finding: Finding): boolean {
  if (finding.ruleId !== "connection-string") return false;
  // LOCAL PATCH: the rule now reports the password alone as secretValue, not the
  // scheme+user+password prefix. Scanning forward from indexOf(secretValue) no
  // longer works — for the canonical postgres:postgres@localhost case the
  // password also occurs as the scheme and as the user, so the first hit is
  // followed by "://..." and the exemption was lost. Re-match the URL shape and
  // compare against the captured host instead.
  let matched = false;
  for (const m of command.matchAll(CONNECTION_URL_RE)) {
    if (m[1] !== finding.secretValue) continue; // a different credential
    matched = true;
    if (!LOCAL_HOST_RE.test(m[2] ?? "")) return false;
  }
  // Fail closed: if the credential cannot be tied to a URL we can inspect, do not
  // exempt it. The previous indexOf form returned true in that case.
  return matched;
}

// ── Output helpers ────────────────────────────────────────────────────────────

// Build the allow-tag hint lines shown to Claude.
// showAllTags: when true, always show [allow-secret] and [allow-pii] hints
// regardless of findings content (used for .env name blocks).
function buildAllowHints(
  exampleContext: string,
  findings: Finding[],
  showAllTags = false,
): string[] {
  const hasSecret =
    showAllTags || findings.some((f) => f.category === "secret");
  const hasPii = showAllTags || findings.some((f) => f.category === "pii");

  const lines: string[] = [];
  if (hasSecret) lines.push("  [allow-secret]  — allow secrets");
  if (hasPii) lines.push("  [allow-pii]     — allow PII");
  lines.push("  [allow-all]     — bypass all sensitive-canary checks");
  lines.push("");

  const example =
    hasSecret && hasPii
      ? "allow-all"
      : hasSecret
        ? "allow-secret"
        : hasPii
          ? "allow-pii"
          : "allow-all";
  lines.push(`Example: "[${example}] ${exampleContext}"`);

  return lines;
}

function block(
  source: string,
  detectionLines: string[],
  allowHints: string[],
): never {
  const bird = randomBird();
  const terminalMessage = [
    "",
    `${bird} sensitive-canary: blocked — ${source}`,
    "",
    ...detectionLines,
    "",
  ].join("\n");

  try {
    const fd = fs.openSync("/dev/tty", "w");
    try {
      fs.writeSync(fd, terminalMessage);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    process.stderr.write(terminalMessage);
  }

  const reasonLines = [
    `${bird} sensitive-canary blocked: ${source}`,
    "",
    ...detectionLines,
    "",
    "To allow this, the user must add an allow tag to their next prompt:",
    ...allowHints,
    "",
    "Please tell the user about this block and suggest the appropriate tag.",
  ];

  process.stdout.write(
    `${JSON.stringify({
      decision: "block",
      reason: reasonLines.join("\n"),
    })}\n`,
  );
  process.exit(2);
}

// ── Core scan logic ───────────────────────────────────────────────────────────

function scanFile(filePath: string, allowTags: Set<string>): void {
  if (isBlockedEnvFile(filePath)) {
    if (allowTags.size > 0) return;
    block(
      filePath,
      [
        "🚫 Blocked: .env and .env.* files contain secrets and must not be read into the conversation.",
      ],
      buildAllowHints(`please read ${filePath}`, [], true),
    );
  }

  let content: string;
  try {
    const raw = fs.readFileSync(filePath);
    // Binary files: scan only the text prefix before the first NUL byte
    const nulIndex = raw.indexOf(0);
    content = (nulIndex === -1 ? raw : raw.subarray(0, nulIndex)).toString(
      "utf8",
    );
    if (content.length === 0) return;
  } catch {
    return;
  }

  const findings = applyAllowTags(dedupeFindings(scan(content)), allowTags);
  if (findings.length === 0) return;

  block(
    filePath,
    [
      "🚫 Blocked: file contains sensitive data",
      "",
      ...findingsToLines(findings),
    ],
    buildAllowHints(`please read ${filePath}`, findings),
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const tool = data.tool_name ?? "";
  const input = data.tool_input ?? {};

  const allowTags = data.transcript_path
    ? loadAllowTagsFromTranscript(data.transcript_path)
    : new Set<string>();

  if (tool === "Read") {
    scanFile(input.file_path ?? "", allowTags);
    process.exit(0);
  }

  if (tool === "Bash") {
    const command = input.command ?? "";

    for (const varName of extractEnvVarNames(command)) {
      const value = process.env[varName];
      if (!value) continue;
      const findings = applyAllowTags(dedupeFindings(scan(value)), allowTags);
      if (findings.length === 0) continue;
      block(
        `bash command: ${command.slice(0, 80)}`,
        [
          `🚫 Blocked: environment variable $${varName} contains sensitive data`,
          "",
          ...findingsToLines(findings),
        ],
        buildAllowHints("please run the command", findings),
      );
    }

    // LOCAL PATCH: skip the generic assignment rules on command *text*. They
    // false-positive on grep/sed patterns like '^API_KEY=adr_(live|...)' and
    // on `TOKEN=$(...)` captures, and any literal in the command is already in
    // the conversation before this hook runs. Specific token formats (AWS,
    // GitHub, etc.) still apply, and file *contents* keep the full rule set.
    const COMMAND_TEXT_EXCLUDED_RULES = new Set([
      "env-assignment",
      "generic-secret",
    ]);
    const cmdFindings = applyAllowTags(
      dedupeFindings(scan(command, COMMAND_TEXT_EXCLUDED_RULES)),
      allowTags,
    ).filter((f) => !isLocalConnectionString(command, f));
    if (cmdFindings.length > 0) {
      block(
        `bash command: ${command.slice(0, 80)}`,
        [
          "🚫 Blocked: bash command contains sensitive data",
          "",
          ...findingsToLines(cmdFindings),
        ],
        buildAllowHints("please run the command", cmdFindings),
      );
    }

    for (const fp of extractFilePathsFromCommand(command)) {
      scanFile(fp, allowTags);
    }

    process.exit(0);
  }

  process.exit(0);
});
