import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  generateUUIDv4,
  decodeJwtPayload,
  escapeHtml,
  resolveBffBaseUrl,
} from "../lib.js";

describe("generateUUIDv4", () => {
  it("returns a string in the canonical UUID v4 format", () => {
    const uuid = generateUUIDv4();
    expect(typeof uuid).toBe("string");
    expect(uuid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
  });

  it("produces unique values across calls", () => {
    const set = new Set(Array.from({ length: 100 }, () => generateUUIDv4()));
    expect(set.size).toBe(100);
  });
});

describe("decodeJwtPayload", () => {
  function makeJwt(payload) {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = btoa(JSON.stringify(payload));
    return `${header}.${body}.signature`;
  }

  beforeEach(() => {
    global.atob = (str) => Buffer.from(str, "base64").toString("binary");
    global.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  });

  it("decodes a valid JWT payload into an object", () => {
    const payload = { sub: "1234", name: "Jules", role: "admin" };
    const token = makeJwt(payload);
    expect(decodeJwtPayload(token)).toEqual(payload);
  });

  it("returns null when the token is null", () => {
    expect(decodeJwtPayload(null)).toBeNull();
  });

  it("returns null when the token is undefined", () => {
    expect(decodeJwtPayload(undefined)).toBeNull();
  });

  it("returns null when the token is not a string", () => {
    expect(decodeJwtPayload(12345)).toBeNull();
  });

  it("returns null when the token does not have 3 parts", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(decodeJwtPayload("only.two")).toBeNull();
    expect(warnSpy).toHaveBeenCalledWith("Token does not have 3 parts.");
    warnSpy.mockRestore();
  });

  it("returns null when the payload is not valid JSON", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const header = btoa(JSON.stringify({ alg: "HS256" }));
    const badBody = btoa("not-json");
    const token = `${header}.${badBody}.sig`;
    expect(decodeJwtPayload(token)).toBeNull();
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });
});

describe("escapeHtml", () => {
  it("escapes all HTML special characters", () => {
    const input = `<script>alert("x" & 'y')</script>`;
    const expected = `&lt;script&gt;alert(&quot;x&quot; &amp; &#039;y&#039;)&lt;/script&gt;`;
    expect(escapeHtml(input)).toBe(expected);
  });

  it("returns an empty string for non-string input", () => {
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(undefined)).toBe("");
    expect(escapeHtml(42)).toBe("");
  });

  it("returns the input unchanged when no special characters are present", () => {
    expect(escapeHtml("hello world")).toBe("hello world");
  });
});

describe("resolveBffBaseUrl", () => {
  it("resolves localhost to the local BFF URL", () => {
    expect(resolveBffBaseUrl("localhost")).toBe("http://localhost:3001");
  });

  it("resolves 127.0.0.1 to the local BFF URL", () => {
    expect(resolveBffBaseUrl("127.0.0.1")).toBe("http://localhost:3001");
  });

  it("resolves the GitHub Pages domain to the production BFF URL", () => {
    expect(resolveBffBaseUrl("julesclements.github.io")).toBe(
      "https://mixed.hdc.company"
    );
  });

  it("resolves the client.hdc.company domain to the production BFF URL", () => {
    expect(resolveBffBaseUrl("client.hdc.company")).toBe(
      "https://mixed.hdc.company"
    );
  });

  it("returns an empty string for unknown hostnames", () => {
    expect(resolveBffBaseUrl("example.com")).toBe("");
  });
});
