import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const HOOK = new URL("../user-prompt-submit-hook.ts", import.meta.url).pathname;
const NODE_FLAGS = ["--experimental-strip-types"];

function runHook(prompt: string) {
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input: JSON.stringify({ prompt }),
    encoding: "utf8",
  });
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

describe("user-prompt-submit-hook — allow (exit 0)", () => {
  it("passes a clean prompt", () => {
    const { exitCode } = runHook("hello, can you help me?");
    expect(exitCode).toBe(0);
  });

  it("passes an empty prompt", () => {
    const { exitCode } = runHook("");
    expect(exitCode).toBe(0);
  });

  it("passes with [allow-all] tag even if secret is present", () => {
    const { exitCode } = runHook("[allow-all] my key is AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(0);
  });

  it("passes with [allow-secret] tag when only secrets are present", () => {
    const { exitCode } = runHook(
      "[allow-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(0);
  });
});

describe("user-prompt-submit-hook — block (exit 2)", () => {
  it("blocks a prompt with an AWS access key", () => {
    const { exitCode, stderr } = runHook("my key is AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("aws-access-key");
    expect(stderr).toContain("blocked");
  });

  it("blocks a prompt with a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const { exitCode, stderr } = runHook(`token: ${jwt}`);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("jwt");
  });

  // FORK (gladstomych): the PII rules are gone; ex-PII content passes.
  it("passes a prompt with emails, cards, and private IPs", () => {
    const { exitCode } = runHook(
      "email user@example.com card: 4111111111111111 host: 192.168.1.1",
    );
    expect(exitCode).toBe(0);
  });

  it("shows [allow-secret] and [allow-all] hints for a secret", () => {
    const { stderr } = runHook("key=AKIAIOSFODNN7EXAMPLE");
    expect(stderr).toContain("[allow-secret]");
    expect(stderr).toContain("[allow-all]");
  });

  it("deduplicates the same secret appearing multiple times", () => {
    const { stderr } = runHook("A=AKIAIOSFODNN7EXAMPLE B=AKIAIOSFODNN7EXAMPLE");
    // aws-access-key finding should appear only once in the output
    const count = (stderr ?? "").split("aws-access-key").length - 1;
    expect(count).toBe(1);
  });

  it("[allow-pii] does not bypass a secret block", () => {
    const { exitCode } = runHook("[allow-pii] my key is AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(2);
  });
});

describe("user-prompt-submit-hook — [mask-xxx] tags", () => {
  it("[mask-secret] with secret shows the actual tag in message", () => {
    const { exitCode, stderr } = runHook(
      "[mask-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-secret]");
    expect(stderr).toContain("[allow-secret]");
  });

  it("[mask-all] with any sensitive data shows masking not supported", () => {
    const { exitCode, stderr } = runHook(
      "[mask-all] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-all]");
  });

  it("[mask-pii] with only secrets falls through to normal block", () => {
    const { exitCode, stderr } = runHook(
      "[mask-pii] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).not.toContain("prompt masking is not supported");
    expect(stderr).toContain("sensitive data detected");
  });

  it("[mask-secret] with clean prompt passes through", () => {
    const { exitCode } = runHook("[mask-secret] hello, can you help me?");
    expect(exitCode).toBe(0);
  });

  it("[mask-unknown] with sensitive data falls through to normal block", () => {
    const { exitCode, stderr } = runHook(
      "[mask-unknown] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).not.toContain("prompt masking is not supported");
    expect(stderr).toContain("sensitive data detected");
  });
});

describe("user-prompt-submit-hook — first-occurrence tag priority", () => {
  it("[allow-secret] before [mask-secret] → passes through (exit 0)", () => {
    const { exitCode } = runHook(
      "[allow-secret] [mask-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(0);
  });

  it("[mask-secret] before [allow-secret] → shows masking not supported (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      "[mask-secret] [allow-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
  });

  it("[allow-all] before [mask-secret] → passes through (exit 0)", () => {
    const { exitCode } = runHook(
      "[allow-all] [mask-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(0);
  });

  it("[mask-all] before [allow-secret] → shows masking not supported (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      "[mask-all] [allow-secret] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
  });

  it("[allow-pii] before [mask-pii] → pii allowed, secret still blocked (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      "[allow-pii] [mask-pii] key AKIAIOSFODNN7EXAMPLE email user@example.com",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("sensitive data detected");
    expect(stderr).not.toContain("prompt masking is not supported");
  });
});

describe("user-prompt-submit-hook — malformed input", () => {
  it("exits 0 on invalid JSON", () => {
    const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
      input: "not json",
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
  });
});
