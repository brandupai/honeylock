#!/usr/bin/env node
"use strict";

const { readFileSync } = require("node:fs");
const path = require("node:path");

const pkg = JSON.parse(readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const runtime = Object.keys(pkg.dependencies ?? {});

if (runtime.length > 0) {
  console.error(`runtime dependencies are not allowed, found: ${runtime.join(", ")}`);
  process.exit(1);
}

const scripts = pkg.scripts ?? {};
const installHooks = ["preinstall", "install", "postinstall"].filter((name) => scripts[name]);
if (installHooks.length > 0) {
  console.error(`install hooks are not allowed in a security tool, found: ${installHooks.join(", ")}`);
  process.exit(1);
}

console.log("ok: no runtime dependencies, no install hooks");
