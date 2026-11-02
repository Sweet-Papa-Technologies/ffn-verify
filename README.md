<p align="center">
  <a href="https://registry.fofo.network">
    <img src="https://raw.githubusercontent.com/Sweet-Papa-Technologies/ffn-verify/main/assets/ffn-verify-banner.jpg" alt="FFN Verified Business: check a business before your agent trusts it." width="100%">
  </a>
</p>

# FFN Verify

Verify a business against [FFN Verified Business](https://registry.fofo.network), from TypeScript or Python, without trusting anyone's server, including ours.

FFN Verified Business publishes signed records about businesses: the domains and phone numbers a business controls, its state registration, and (at higher levels) its license and insurance. Each fact has its source and the date it was checked. These libraries fetch a record and check all of it themselves: the registry's signature against pinned keys, the business's own signature, the business's domain pointing back to the registry, and the current status of every fact.

| Language   | Package                                                                                     | Folder                                                   |
| ---------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| TypeScript | [`@fofonet/verify-business`](https://www.npmjs.com/package/@fofonet/verify-business) on npm | [`packages/verify-business/`](packages/verify-business/) |
| Python     | [`ffn-verify`](https://pypi.org/project/ffn-verify/) on PyPI                                | [`python/`](python/)                                     |

Both implementations pass the same test vectors ([`vectors/business/v1.json`](vectors/business/v1.json)), so they give the same answer for the same record.

## Quick start

```sh
npm install @fofonet/verify-business
```

```ts
import { verifyBusiness, FFN_BUSINESS_REGISTRY } from '@fofonet/verify-business';

const r = await verifyBusiness('sweetpapatechnologies.com', {
  registry: FFN_BUSINESS_REGISTRY,
  observed: { phone: '+1 510-497-0742' }, // what your agent was given, if anything
});

if (r.verified && r.observedMatches) {
  console.log(r.summary); // one paragraph, safe to show a person
}
```

```sh
pip install ffn-verify
```

```python
from ffn_verify import FFN_BUSINESS_REGISTRY, verify_business

r = verify_business(
    "sweetpapatechnologies.com",
    registry=FFN_BUSINESS_REGISTRY,
    observed={"phone": "+1 510-497-0742"},
)
if r["verified"] and r["observedMatches"]:
    print(r["summary"])
```

You can also start from a phone number: `verifyBusiness({ phone: '+15104970742' }, …)` in TypeScript, `verify_business(phone="+15104970742", …)` in Python.

## What a result means

- **`verified`** is true when the record, its signatures and the business's domain binding check out, and the facts for at least Level 1 are current. It says the registry vouches for these facts today. It is not a rating, a review or a recommendation, and paying never changes a record.
- **`observedMatches`** is false when something you passed in `observed` (a name, phone or address your agent saw) differs from the record. Check it whenever you pass `observed`: a hacked website can swap in its own phone number while the record stays verified. `mismatches` says what differed.
- **A verified phone** means the business controls that number when _you_ call it. It never means an incoming call or text from that number is from the business.
- **`facts`** lists each fact with its status (`valid`, `expired`, `revoked`, `suspended`, `unknown`, `invalid`), its checks, and a one-sentence summary.
- **`level`**: 1 Registered (domain, phone and state registration), 2 Licensed and insured, 3 Owner verified.

When `verified` is false, `failure.code` says why:

| Code                   | Meaning                                                                        |
| ---------------------- | ------------------------------------------------------------------------------ |
| `bad_domain`           | The domain isn't a valid domain name.                                          |
| `bad_phone`            | The phone number isn't valid.                                                  |
| `not_in_registry`      | The registry has no listing for this domain or phone.                          |
| `domain_not_listed`    | The record found doesn't list this domain.                                     |
| `phone_not_listed`     | The record found doesn't list this phone.                                      |
| `registry_unavailable` | The registry couldn't be reached.                                              |
| `bad_record`           | The registry's record is malformed or its signature doesn't verify.            |
| `bad_profile`          | The business's signed profile doesn't verify.                                  |
| `binding_unreachable`  | The business's domain couldn't be checked (its did.json or DNS).               |
| `binding_failed`       | The business's domain doesn't point back to this registry entry.               |
| `delegation_invalid`   | The business's authorization for the registry doesn't verify or isn't current. |
| `not_verified`         | No current fact supports even Level 1.                                         |

## What the libraries trust and fetch

- **Pinned registry keys.** `FFN_BUSINESS_REGISTRY` carries the SHA-256 thumbprints ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)) of the registry's signing key and its standby key. Anything signed by another key fails, even if the registry's own did.json lists it. Every known FFN registry is pinned in every function, including presentation checks.
- **Network reads**, all over HTTPS, with no redirects followed, a 10-second limit per request and a size limit on every response:
  - the registry: the record and its status lists;
  - the business's `/.well-known/did.json`;
  - its `_ffn` DNS TXT record, through DNS-over-HTTPS (Cloudflare by default; pass your own resolver with `dns`).
- **Nothing else**, and nothing before trust is decided: a presentation from an issuer you don't accept, or a delegation chain that doesn't start at a root you accept, fails without a single request. Requests to private, loopback and link-local addresses are refused. If you run the verifier inside a sensitive network, also send its traffic through an egress proxy, which is the only full defense against DNS rebinding.

## Without a library

- **HTTP:** `GET https://registry.fofo.network/v1/verify?domain=…` returns the same result, computed by the registry. That's simpler, but you trust the registry's server instead of checking the signatures yourself. See [`/openapi.json`](https://registry.fofo.network/openapi.json).
- **MCP:** the registry runs an MCP server with `lookup_business`, `verify_business` and `verify_presentation` tools. See [the guide for agents](https://registry.fofo.network/agents#mcp).

## Links

- [FFN Verified Business](https://registry.fofo.network): look up a business, or list yours
- [Guide for AI agents](https://registry.fofo.network/agents) · [OpenAPI](https://registry.fofo.network/openapi.json) · [llms.txt](https://registry.fofo.network/llms.txt)
- [Dispute a record](https://registry.fofo.network/dispute)
- [FoFo Network](https://fofo.network) · [FFN Pass](https://pass.fofo.network)
- [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## Development

This repository is exported from Sweet Papa Technologies' monorepo, where the registry and these libraries are developed together. Issues and pull requests are welcome here; accepted changes are applied upstream and come back with the next export.

```sh
pnpm install && pnpm test          # TypeScript: build, unit tests, vectors
cd python && pip install -e . && python -m unittest discover -s tests   # Python: unit tests, vectors
```

## License

[Apache-2.0](LICENSE). Copyright 2026 Sweet Papa Technologies LLC.
