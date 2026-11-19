import assert from "node:assert/strict";
import { entropyBitsPerChar } from "../src/util";
import { test } from "node:test";
import {
  decodeLayers,
  findInvisibleChars,
  normalizeShell,
  percentDecodeIterative,
  stripSqlComments,
} from "../src/decode";

test("percent decoding is iterative, so double encoding is seen", () => {
  assert.equal(percentDecodeIterative("%252e%252e/etc"), "../etc");
  assert.equal(percentDecodeIterative("%252e%252e/%252e%252e/etc/shadow"), "../../etc/shadow");
  assert.equal(percentDecodeIterative("%2e%2e/%2e%2e"), "../..");
  assert.equal(percentDecodeIterative("plain/path"), "plain/path");
});

test("a stray percent sign does not throw", () => {
  assert.equal(percentDecodeIterative("100% sure"), "100% sure");
  assert.equal(percentDecodeIterative("%zz%41"), "%zzA");
});

test("shell normalization removes quoting and sorts flag groups", () => {
  assert.equal(normalizeShell("r'm' -r -f /"), "rm -fr /");
  assert.equal(normalizeShell('rm -"r"f /'), "rm -rf /");
  assert.equal(normalizeShell("ls   -la"), "ls -la");
});

test("SQL comments are removed before matching", () => {
  assert.equal(stripSqlComments("DROP/**/TABLE users"), "DROP TABLE users");
  assert.equal(stripSqlComments("SELECT 1 -- trailing\n"), "SELECT 1");
});

test("invisible characters are classified", () => {
  assert.deepEqual(findInvisibleChars("abc"), []);
  const tag = findInvisibleChars("a\u{E0041}b");
  assert.equal(tag[0]?.category, "tag");
  const bidi = findInvisibleChars("a\u202Eb");
  assert.equal(bidi[0]?.category, "bidi");
  const zw = findInvisibleChars("a\u200Bb");
  assert.equal(zw[0]?.category, "zero-width");
});

test("entropy separates a secret from a dictionary word", () => {
  assert.ok(entropyBitsPerChar("contributing") < 3.6);
  assert.ok(entropyBitsPerChar("x9F2kQ7pL0zR4mT8vB1n") > 4.0);
});

test("base64 and hex layers are decoded", () => {
  const encoded = Buffer.from("secret-value-inside").toString("base64");
  assert.deepEqual(decodeLayers(encoded), ["secret-value-inside"]);
  assert.deepEqual(decodeLayers("68656c6c6f2d776f726c64"), ["hello-world"]);
});
