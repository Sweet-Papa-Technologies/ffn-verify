# Security policy

FFN Verify decides whether an AI agent or an app trusts a business. A bug that makes it report a business as verified when it isn't, accept a key it shouldn't, or fetch somewhere it shouldn't is a security bug, and we want to hear about it.

## Reporting a vulnerability

Please report privately, not in a public issue:

- **GitHub:** the [Report a vulnerability](https://github.com/Sweet-Papa-Technologies/ffn-verify/security/advisories/new) form on this repository, or
- **Email:** fterry@sweetpapatechnologies.com, with "FFN Verify security" in the subject.

Include the version, a minimal reproduction (a test vector is ideal), and what you expected. We'll confirm we received it, keep you updated, and credit you in the advisory if you'd like.

## Scope

- The TypeScript package `@fofonet/verify-business` and the Python package `ffn-verify`.
- The registry at https://registry.fofo.network, including its HTTP API and MCP server. A record that's wrong rather than a software bug goes through [the dispute page](https://registry.fofo.network/dispute) instead.

## Supported versions

Security fixes go into the latest release of each package. Please upgrade to it before reporting.

## Registry keys

The packages pin the registry's signing keys by thumbprint. If a registry key is ever compromised, we'll publish a security advisory here, rotate to the published standby key, and release new versions of both packages with updated pins.
