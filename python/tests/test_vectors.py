"""Replays ffn-pass/vectors/business/v1.json offline, as the TS suite
(packages/verify-business/test/vectors.test.ts) does. One test per case, read from
the file as it is on disk, so regenerated vectors are picked up unchanged.

The file is found in the repository, or wherever FFN_VECTORS points; without it these
tests skip. A case may query by domain or by phone, carry per-case ``http``/``dns``
overrides, and expect a fetch count; a field this runner doesn't know fails the case
by name (so a new kind of expectation is never silently unchecked).
"""

from __future__ import annotations

import base64
import re
import unittest

from fixtures import NO_VECTORS, load_world

from ffn_verify import static_txt, verify_business, verify_presentation

WORLD = load_world()
NOT_A_RATING = re.compile(r"\b(trusted|recommended|endorsed)\b", re.IGNORECASE)

CASE_FIELDS = {"name", "description", "input", "expected", "http", "dns"}
HTTP_FIELDS = {"status", "contentType", "body", "bodyBase64", "error"}
BUSINESS_EXPECTED = {"verified", "level", "binding", "lowerAssurance", "failure", "mismatches", "facts",
                     "summaryIncludes", "warningsInclude", "reasons", "scope", "observedMatches", "phone", "domain",
                     "delegation"}
PRESENTATION_EXPECTED = {"verified", "code", "subject", "root", "delegate", "scope", "issuer", "vct",
                         "messageIncludes"}
# However the generator spells "how many requests the verifier made".
FETCH_EXPECTED = {"fetches", "fetchCount", "requests", "noFetch", "noFetches", "maxFetches"}


class Http:
    """The world's http table (with a case's overrides) as a fetch, counting requests."""

    def __init__(self, table: dict):
        self.table = table
        self.log: list[str] = []

    def __call__(self, url: str, headers: dict | None = None) -> tuple[int, str, bytes]:
        self.log.append(url)
        hit = self.table.get(url)
        if hit is None:
            return 404, "text/plain", b"not found"
        unknown = set(hit) - HTTP_FIELDS
        if unknown:
            raise AssertionError(f"the vector http entry for {url} uses fields this runner doesn't know: "
                                 f"{sorted(unknown)}; teach tests/test_vectors.py")
        if "error" in hit:
            raise ConnectionError("fetch failed")
        body = base64.b64decode(hit["bodyBase64"]) if "bodyBase64" in hit else hit["body"].encode("utf-8")
        return hit["status"], hit["contentType"], body


def world_for(case: dict) -> tuple[Http, object]:
    return Http({**WORLD["http"], **(case.get("http") or {})}), static_txt({**WORLD["dns"], **(case.get("dns") or {})})


def run_business(domain: str | None = None, observed: dict | None = None, *, phone: str | None = None,
                 fetch: Http | None = None, dns: object = None) -> dict:
    return verify_business(domain, phone=phone, registry=WORLD["registry"], fetch=fetch or Http(WORLD["http"]),
                           dns=dns or static_txt(WORLD["dns"]), now=WORLD["now"], observed=observed)


@unittest.skipUnless(WORLD, NO_VECTORS)
class Vectors(unittest.TestCase):
    def check_unknown(self, e: dict, known: set[str]) -> None:
        unknown = set(e) - known - FETCH_EXPECTED
        self.assertFalse(unknown, f"expectations this runner doesn't check yet: {sorted(unknown)}; "
                                  "teach tests/test_vectors.py")

    def check_fetches(self, log: list[str], e: dict) -> None:
        for key in ("fetches", "fetchCount", "requests"):
            if key in e:
                want = e[key]
                if isinstance(want, list):
                    self.assertEqual(log, want)
                else:
                    self.assertEqual(len(log), want, log)
        if e.get("noFetch") or e.get("noFetches"):
            self.assertEqual(log, [])
        if "maxFetches" in e:
            self.assertLessEqual(len(log), e["maxFetches"], log)

    def check_business(self, r: dict, e: dict) -> None:
        self.check_unknown(e, BUSINESS_EXPECTED)
        if "verified" in e:
            self.assertEqual(r["verified"], e["verified"], r["summary"])
        if "level" in e:
            self.assertEqual(r["level"], e["level"])
        if "binding" in e:
            self.assertEqual(r["binding"]["status"], e["binding"])
        if "lowerAssurance" in e:
            self.assertEqual(r["binding"]["lowerAssurance"], e["lowerAssurance"])
        if "failure" in e:
            self.assertEqual((r.get("failure") or {}).get("code"), e["failure"], r["summary"])
        if "mismatches" in e:
            self.assertEqual(len(r["mismatches"]), e["mismatches"], " | ".join(r["mismatches"]))
        if "observedMatches" in e:
            self.assertEqual(r["observedMatches"], e["observedMatches"], " | ".join(r["mismatches"]))
        if "phone" in e:
            self.assertEqual(r.get("phone"), e["phone"])
        if "domain" in e:
            self.assertEqual(r["domain"], e["domain"])
        if "delegation" in e:
            want = e["delegation"]
            self.assertEqual(r["delegation"]["valid"], want if isinstance(want, bool) else want.get("valid"))
        for kind, status in (e.get("facts") or {}).items():
            fact = next((f for f in r["facts"] if f["kind"] == kind), {})
            self.assertEqual(fact.get("status"), status, kind)
        if e.get("summaryIncludes"):
            self.assertIn(e["summaryIncludes"], r["summary"])
        if e.get("warningsInclude"):
            self.assertIn(e["warningsInclude"], " | ".join(r["warnings"]))
        for kind, reason in (e.get("reasons") or {}).items():
            fact = next((f for f in r["facts"] if f["kind"] == kind), {})
            self.assertEqual(fact.get("reason"), reason, kind)
        if "scope" in e:
            # The assertion codes the verified scope keeps, or None for a record without one.
            scope = r.get("scope")
            self.assertEqual([a["code"] for a in scope["asserts"]] if scope else None, e["scope"])
        # Present on every result, and the two always agree.
        self.assertEqual(r["observedMatches"], not r["mismatches"])

    def check_presentation(self, r: dict, e: dict) -> None:
        self.check_unknown(e, PRESENTATION_EXPECTED)
        self.assertEqual(r["verified"], e["verified"], r.get("message", ""))
        if not r["verified"] and "code" in e:
            self.assertEqual(r["code"], e["code"], r.get("message", ""))
        if not r["verified"] and "messageIncludes" in e:
            self.assertIn(e["messageIncludes"], r["message"])
        if r["verified"]:
            for key in ("subject", "issuer", "vct"):
                if e.get(key):
                    self.assertEqual(r[key], e[key])
            if e.get("root"):
                self.assertEqual((r.get("delegation") or {}).get("root"), e["root"])
            if e.get("delegate"):
                self.assertEqual((r.get("delegation") or {}).get("delegate"), e["delegate"])
            if e.get("scope"):
                self.assertEqual((r.get("delegation") or {}).get("scope"), e["scope"])

    def test_summary_states_facts_with_dates_in_plain_words(self) -> None:
        r = run_business("acme-hvac.example")
        self.assertRegex(
            r["summary"],
            r"^acme-hvac\.example belongs to Acme HVAC Inc\., listed in the FFN Verified Business registry at Level 2")
        self.assertRegex(r["summary"], r"license 1000003 \(C-20\) is active until")
        self.assertIn("Not checked: verified representative.", r["summary"])
        self.assertIn("not a rating or a recommendation", r["summary"])


def _case_test(case: dict):
    def test(self: Vectors) -> None:
        unknown = set(case) - CASE_FIELDS
        self.assertFalse(unknown, f"case fields this runner doesn't know: {sorted(unknown)}")
        c = case["input"]
        fetch, dns = world_for(case)
        if c["type"] == "verifyBusiness":
            query = {"phone": c["phone"]} if "phone" in c and "domain" not in c else {"domain": c["domain"]}
            r = run_business(observed=c.get("observed"), fetch=fetch, dns=dns, **query)
            self.check_business(r, case["expected"])
            self.assertNotRegex(r["summary"], NOT_A_RATING)
        elif c["type"] == "verifyPresentation":
            presentation_input = {k: v for k, v in c.items() if k != "type"}
            self.check_presentation(verify_presentation(presentation_input, fetch=fetch, now=WORLD["now"]),
                                    case["expected"])
        else:
            self.fail(f"a case type this runner doesn't know: {c['type']}")
        self.check_fetches(fetch.log, case["expected"])

    test.__doc__ = f"{case['name']}: {case['description']}"
    return test


for _case in (WORLD or {}).get("cases", []):
    setattr(Vectors, "test_case_" + re.sub(r"\W", "_", _case["name"]), _case_test(_case))


if __name__ == "__main__":
    unittest.main()
