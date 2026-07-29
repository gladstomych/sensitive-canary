import { describe, expect, it } from "vitest";
import { entropy, isNonLiteralValue, scan } from "../rules.ts";

// Regression suite for the structural non-literal filter.
//
// Every case in "real false positives" below was observed blocking a real read or
// bash call. Every case in "must still block" is the safety boundary — if one of
// those ever passes, the filter has been widened too far.

const SCHEME = "postgre" + "sql"; // keeps a literal credential URL out of this file
const INTERP = "${" + "DB_PASSWORD" + "}";

// Deterministic high-entropy filler. A repeated character would deflate entropy
// below the rule thresholds and make a "real secret" case pass for the wrong
// reason, which is a trap we hit while investigating.
function rnd(n: number): string {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let x = 12345;
  let s = "";
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    s += a[x % a.length];
  }
  return s;
}

const fired = (text: string, ruleId: string): boolean =>
  scan(text).some((f) => f.ruleId === ruleId);

describe("isNonLiteralValue — references", () => {
  it.each([
    ["$DATABASE_PASSWORD"],
    // These are shell-interpolation fixtures, not mis-typed template literals:
    // the string under test must literally contain "${...}".
    // biome-ignore-start lint/suspicious/noTemplateCurlyInString: intentional fixture
    ["${DATABASE_PASSWORD}"],
    ["${DATABASE_PASSWORD:-fallback}"],
    ["${DATABASE_PASSWORD:?must be set}"],
    // biome-ignore-end lint/suspicious/noTemplateCurlyInString: intentional fixture
    ["settings.anthropic_api_key"],
    ["settings.brave_api_key"],
    ["config.db.password"],
    ["os.environ"],
    ['os.environ["ANTHROPIC_API_KEY"]'],
    ["process.env.ANTHROPIC_API_KEY"],
    ["Deno.env.get"],
    ["{{ vault_db_password }}"],
    ["<YOUR_API_KEY_HERE>"],
    ["%(password)s"],
  ])("treats %s as a reference", (value) => {
    expect(isNonLiteralValue(value)).toBe(true);
  });

  it("unwraps quotes and trailing separators before testing", () => {
    // env-assignment captures with \S{8,}, so the value arrives still wrapped.
    expect(isNonLiteralValue(`"${INTERP}",`)).toBe(true);
    expect(isNonLiteralValue(`'settings.api_key';`)).toBe(true);
  });
});

describe("isNonLiteralValue — placeholders", () => {
  it.each([
    ["changeme"],
    ["changeme123"],
    ["change-me"],
    ["replaceme"],
    ["placeholder"],
    ["ci-placeholder"],
    ["example"],
    ["dummy"],
    ["redacted"],
    ["your-key-here"],
    ["YOUR_TOKEN"],
    ["xxxxxxxx"],
    ["********"],
  ])("treats %s as a placeholder", (value) => {
    expect(isNonLiteralValue(value)).toBe(true);
  });
});

describe("isNonLiteralValue — must NOT exempt real credentials", () => {
  it.each([
    [rnd(24)],
    [rnd(40)],
    [`sk-ant-api03-${rnd(90)}`],
    // A placeholder word as a PREFIX must not launder the rest. This is the
    // whole reason every pattern is anchored.
    [`changeme-${rnd(40)}`],
    [`placeholder${rnd(30)}`],
    ["your-key-here-8Kd93mZqLp01"],
    // Weak but real: short, low entropy, still a credential. These read like
    // placeholders, which is exactly why they are NOT in PLACEHOLDER_WORDS —
    // exempting them would hide real weak credentials. Pinned so they cannot be
    // added back casually.
    ["hunter2!"],
    ["admin"],
    ["postgres"],
    ["password"],
    ["passwd"],
    ["secret"],
  ])("does not exempt %s", (value) => {
    expect(isNonLiteralValue(value)).toBe(false);
  });

  it("keeps detecting the canonical weak connection string", () => {
    // Guards the pre-existing rules.test.ts case: the password here is the literal
    // word "password", and it must still be reported.
    const findings = scan(`${SCHEME}://user:password@localhost/mydb`);
    expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
  });
});

describe("entropy cannot substitute for this filter", () => {
  it("scores a reference above a real credential", () => {
    // The finding that motivated a structural filter rather than a higher
    // entropyThreshold: no threshold can separate these two.
    const reference = entropy("settings.anthropic_api_key");
    const real = entropy(rnd(24));
    expect(reference).toBeGreaterThan(3.5);
    expect(Math.abs(reference - real)).toBeLessThan(0.5);
  });
});

describe("scan() — the three rules that false-positived", () => {
  it("generic-secret: attribute reference passes", () => {
    expect(
      fired("        api_key=settings.anthropic_api_key,", "generic-secret"),
    ).toBe(false);
  });

  it("generic-secret: process.env reference passes", () => {
    expect(
      fired("const k = process.env.ANTHROPIC_API_KEY_VALUE", "generic-secret"),
    ).toBe(false);
  });

  it("generic-secret: a literal key still blocks", () => {
    expect(fired(`api_key='sk-ant-api03-${rnd(90)}'`, "generic-secret")).toBe(
      true,
    );
  });

  it("env-assignment: ci-placeholder passes", () => {
    expect(fired("POSTGRES_PASSWORD=ci-placeholder", "env-assignment")).toBe(
      false,
    );
  });

  it("env-assignment: quoted interpolation passes", () => {
    expect(fired(`POSTGRES_PASSWORD="${INTERP}"`, "env-assignment")).toBe(
      false,
    );
  });

  it("env-assignment: a literal password still blocks", () => {
    expect(fired(`POSTGRES_PASSWORD=${rnd(24)}`, "env-assignment")).toBe(true);
  });

  it("env-assignment: placeholder-prefixed real value still blocks", () => {
    expect(fired(`API_KEY=changeme-${rnd(40)}`, "env-assignment")).toBe(true);
  });

  it("connection-string: interpolated password passes", () => {
    const url = `${SCHEME}://matthew:${INTERP}@postgres:5432/matthew`;
    expect(fired(url, "connection-string")).toBe(false);
  });

  it("connection-string: a literal password still blocks", () => {
    const url = `${SCHEME}://admin:${rnd(20)}@db.prod.example.com:5432/app`;
    expect(fired(url, "connection-string")).toBe(true);
  });

  it("connection-string: weak-but-real password still blocks (no entropy gate)", () => {
    // Guards the decision not to add an entropyThreshold to this rule.
    const url = `${SCHEME}://admin:admin@db.prod.example.com:5432/app`;
    expect(fired(url, "connection-string")).toBe(true);
  });

  it("connection-string: reports the password, not the whole URL", () => {
    const pw = rnd(20);
    const url = `${SCHEME}://admin:${pw}@db.prod.example.com:5432/app`;
    const finding = scan(url).find((f) => f.ruleId === "connection-string");
    expect(finding?.secretValue).toBe(pw);
  });
});

describe("specific-format rules are unaffected", () => {
  it("still catches a GitHub PAT", () => {
    expect(
      scan(`token: ghp_${rnd(36)}`).some((f) => f.ruleId === "github-pat"),
    ).toBe(true);
  });

  it("still catches an AWS access key", () => {
    expect(
      scan("AKIAIOSFODNN7EXAMPLE").some((f) => f.ruleId === "aws-access-key"),
    ).toBe(true);
  });
});
