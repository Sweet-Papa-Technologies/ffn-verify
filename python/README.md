<p align="center">
  <a href="https://registry.fofo.network">
    <img src="https://raw.githubusercontent.com/Sweet-Papa-Technologies/ffn-verify/main/assets/ffn-verify-banner.jpg" alt="FFN Verified Business: check a business before your agent trusts it." width="100%">
  </a>
</p>
<p align="center">
  <a href="https://github.com/Sweet-Papa-Technologies/ffn-verify/actions/workflows/ci.yml"><img src="https://github.com/Sweet-Papa-Technologies/ffn-verify/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://pypi.org/project/ffn-verify/"><img src="https://img.shields.io/pypi/v/ffn-verify?label=PyPI" alt="PyPI"></a>
  <a href="https://pypi.org/project/ffn-verify/"><img src="https://img.shields.io/pypi/pyversions/ffn-verify" alt="Python versions"></a>
  <a href="https://github.com/Sweet-Papa-Technologies/ffn-verify/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"></a>
</p>

# ffn-verify

Verify a business against [FFN Verified Business](https://registry.fofo.network) before your agent or app trusts it. Give it a domain or a phone number; it fetches the business's signed record and checks all of it in your own process: the registry's signature against pinned keys, the business's own signature, the business's domain pointing back to the registry, and the current status of every fact.

TypeScript: [`@fofonet/verify-business`](https://www.npmjs.com/package/@fofonet/verify-business). Both pass the same [test vectors](https://github.com/Sweet-Papa-Technologies/ffn-verify/tree/main/vectors).

```sh
pip install ffn-verify
```

Python 3.11 or later. Its only dependency is `cryptography`.

## Verify a business

```python
from ffn_verify import FFN_BUSINESS_REGISTRY, verify_business

r = verify_business(
    "sweetpapatechnologies.com",
    registry=FFN_BUSINESS_REGISTRY,
    observed={"name": "Sweet Papa Technologies", "phone": "+1 510-497-0742"},
)

if r["verified"] and r["observedMatches"]:
    print(r["level"], r["levelName"])  # 1 Registered
    print(r["summary"])
elif r["verified"]:
    print("Listed, but what you were told differs:", r["mismatches"])
else:
    print(r["failure"]["code"], r["failure"]["message"])
```

By phone: `verify_business(phone="+15104970742", registry=FFN_BUSINESS_REGISTRY)`. Pass exactly one of `domain` or `phone`. A phone query only counts the business's official channels when the registry confirmed that number.

Results are plain dicts with the same keys as the TypeScript package and the HTTP API (`verified`, `observedMatches`, `level`, `levelName`, `business`, `facts`, `binding`, `scope`, `mismatches`, `warnings`, `failure`, `summary`, `checkedAt`). Their meanings, and every `failure.code`, are in the [repository README](https://github.com/Sweet-Papa-Technologies/ffn-verify#what-a-result-means).

- **`verified`**: the record, its signatures and the domain binding check out, and the facts for at least Level 1 are current. It's not a rating or a recommendation.
- **`observedMatches`**: `False` when anything in `observed` differs from the record. Always check it when you pass `observed`: a hacked site can swap in its own phone while the record stays verified.
- A verified phone means the business controls that number when _you_ call it. It never means an incoming call or text from that number is from the business.

### Options

| Keyword             | Default                   | Meaning                                                                                     |
| ------------------- | ------------------------- | ------------------------------------------------------------------------------------------- |
| `registry`          | required                  | The registry to trust. `FFN_BUSINESS_REGISTRY` is the production one, with its keys pinned. |
| `observed`          | `None`                    | What your agent was told: `{"name", "phone", "address"}`, any of them.                      |
| `timeout`           | `10.0`                    | Seconds allowed for each request, body included.                                            |
| `fetch`             | built in (urllib)         | Your own fetch, for example through an egress proxy. Size limits and deadlines still apply. |
| `dns`               | Cloudflare DNS over HTTPS | A TXT resolver, e.g. `doh_resolver("google")`.                                              |
| `resolver`, `store` | built in                  | A DID resolver and a status-list cache, to share between calls.                             |

`lookup_business(registry=..., domain=...)` (or `phone=`) returns the record without the full check. Only the registry's signature is verified, so use `verify_business` before trusting anything in it.

## Verify a presentation

```python
from ffn_verify import FFN_BUSINESS_REGISTRY, verify_presentation

p = verify_presentation(
    {
        "presentation": presentation,  # the SD-JWT presentation you received
        "nonce": nonce,  # the nonce you issued
        "audience": "https://your-agent.example",
        "issuers": [FFN_BUSINESS_REGISTRY["did"]],
    },
    registry=FFN_BUSINESS_REGISTRY,
)
if p["verified"]:
    print(p["subject"], p["vct"], p["claims"])
```

Delegations take `chain` (parent delegations, nearest first) and `roots` (the DIDs a chain may start at). Credentials from an issuer you don't accept, and chains that don't start at a root you accept, fail before anything is fetched.

## Security

- **Pinned keys.** `FFN_BUSINESS_REGISTRY` carries the RFC 7638 thumbprints of the registry's signing key and its standby key. Every known FFN registry is pinned in every function; a custom registry passes `keyThumbprints`.
- **What it fetches:** the registry (the record and its status lists), the business's `did.json`, and its DNS TXT record over DNS over HTTPS. Everything is HTTPS-only, with no redirects, a size limit on every response and a total deadline on every request.
- **What it refuses:** private, loopback and link-local addresses, `localhost`, `.local` and `.internal` names. Status lists must be signed by their host's own DID. If you run it inside a sensitive network, send its traffic through an egress proxy as well; that's the only full defense against DNS rebinding.

Found a problem? See the [security policy](https://github.com/Sweet-Papa-Technologies/ffn-verify/security/policy).

## Without a library

`GET https://registry.fofo.network/v1/verify?domain=…` returns the same result computed by the registry ([OpenAPI](https://registry.fofo.network/openapi.json)), and the registry runs an [MCP server](https://registry.fofo.network/agents#mcp). Both are simpler, but then you trust the registry's server instead of checking its signatures yourself.

## Development

```sh
pip install -e .
python -m unittest discover -s tests
```

The tests replay `../vectors/business/v1.json` when they run inside the [source repository](https://github.com/Sweet-Papa-Technologies/ffn-verify) (or wherever `FFN_VECTORS` points), and skip those cases with a reason otherwise.

## Links

[FFN Verified Business](https://registry.fofo.network) · [Guide for agents](https://registry.fofo.network/agents) · [llms.txt](https://registry.fofo.network/llms.txt) · [Source](https://github.com/Sweet-Papa-Technologies/ffn-verify) · [Changelog](https://github.com/Sweet-Papa-Technologies/ffn-verify/blob/main/CHANGELOG.md) · [FoFo Network](https://fofo.network)

Apache-2.0. Copyright 2026 Sweet Papa Technologies LLC.
