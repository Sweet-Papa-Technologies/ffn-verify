"""Registry key pins and the scope of assertion, on the vector world, as the TS
suite's pins-and-scope.test.ts. The world's registry did.json lists #records-1
(signing), #records-2 (standby, no relationship) and #records-9 (an assertion key
nobody pins)."""

from __future__ import annotations

import json
import re
import unittest

from fixtures import NO_VECTORS, REPO_PASS, load_world

from ffn_verify import FFN_BUSINESS_REGISTRY, VerificationError, lookup_business, static_txt, verify_business

ROOT = REPO_PASS
WORLD = load_world() or {"http": {}, "dns": {}, "registry": {}, "now": 0}
HAVE_WORLD = bool(WORLD["http"])
DID_URL = "https://registry.test/.well-known/did.json"
DNS = static_txt(WORLD["dns"])
NETWORKS_TS = ROOT / "packages" / "door-core" / "src" / "networks.ts"
CALLER_ID = ("A verified phone number shows the business controls it when you call it, not that a call or text "
             "you receive comes from the business.")


def fetch_from(http: dict):
    def fetch(url: str, headers: dict | None = None) -> tuple[int, str, bytes]:
        hit = http.get(url)
        if hit is None:
            return 404, "text/plain", b"not found"
        if "error" in hit:
            raise ConnectionError("fetch failed")
        return hit["status"], hit["contentType"], hit["body"].encode("utf-8")
    return fetch


FETCH = fetch_from(WORLD["http"])


def run(domain: str, registry: dict | None = None, fetch=FETCH) -> dict:
    return verify_business(domain, registry=registry or WORLD["registry"], fetch=fetch, dns=DNS, now=WORLD["now"])


def promoted():
    """The world after the standby is promoted: #records-2 becomes an assertion key too."""
    doc = json.loads(WORLD["http"][DID_URL]["body"])
    doc["assertionMethod"] = [*doc.get("assertionMethod", []), f"{WORLD['registry']['did']}#records-2"]
    return fetch_from({**WORLD["http"], DID_URL: {"status": 200, "contentType": "application/json",
                                                  "body": json.dumps(doc)}})


@unittest.skipUnless(HAVE_WORLD, NO_VECTORS)
class Pins(unittest.TestCase):
    def test_reject_a_key_did_json_lists_but_the_verifier_does_not_pin(self) -> None:
        unpinned = {k: v for k, v in WORLD["registry"].items() if k != "keyThumbprints"}
        self.assertTrue(run("unpinned-key.example", unpinned)["verified"])
        pinned = run("unpinned-key.example")
        self.assertFalse(pinned["verified"])
        self.assertEqual(pinned["failure"]["code"], "bad_record")
        self.assertIn("not one of the registry keys this verifier pins", pinned["failure"]["message"])
        smuggled = run("smuggled-license.example")
        self.assertEqual(next(f for f in smuggled["facts"] if f["kind"] == "license")["status"], "invalid")
        self.assertEqual(run("smuggled-license.example", unpinned)["level"], 2)

    def test_cover_the_standby_so_a_planned_rotation_keeps_verifiers_working(self) -> None:
        self.assertEqual(run("standby-key.example")["failure"]["code"], "bad_record")
        after = run("standby-key.example", fetch=promoted())
        self.assertTrue(after["verified"], after["summary"])
        self.assertEqual(after["level"], 2)
        self.assertTrue(run("acme-hvac.example", fetch=promoted())["verified"])
        old_pins_only = {**WORLD["registry"], "keyThumbprints": WORLD["registry"]["keyThumbprints"][:1]}
        self.assertEqual(run("standby-key.example", old_pins_only, promoted())["failure"]["code"], "bad_record")

    def test_apply_to_lookups(self) -> None:
        with self.assertRaisesRegex(VerificationError, "pins"):
            lookup_business(registry=WORLD["registry"], domain="unpinned-key.example", fetch=FETCH, now=WORLD["now"])

    @unittest.skipUnless(NETWORKS_TS.is_file(), "the TypeScript sources are not here")
    def test_production_pins_match_the_typescript(self) -> None:
        self.assertEqual(FFN_BUSINESS_REGISTRY["origin"], "https://registry.fofo.network")
        self.assertEqual(FFN_BUSINESS_REGISTRY["did"], "did:web:registry.fofo.network")
        ts = NETWORKS_TS.read_text("utf-8")
        block = re.search(r"const PRODUCTION_REGISTRY_KEYS = \[(.*?)\];", ts, re.S).group(1)
        self.assertEqual(FFN_BUSINESS_REGISTRY["keyThumbprints"], re.findall(r"^\s*'([A-Za-z0-9_-]+)',", block, re.M))
        self.assertIn("ha2yRH_LpeVyIJR5KvD_3m10ZQCbe1ppRqo5Swo7B6k", FFN_BUSINESS_REGISTRY["keyThumbprints"])


@unittest.skipUnless(HAVE_WORLD, NO_VECTORS)
class Scope(unittest.TestCase):
    def test_states_what_was_verified_what_never_is_and_where_it_is_explained(self) -> None:
        r = run("acme-hvac.example")
        scope = r["scope"]
        self.assertEqual(scope["explanation"], "https://registry.test/how-it-works#scope")
        codes = [d["code"] for d in scope["doesNotAssert"]]
        self.assertEqual(codes, ["rating", "ranking", "recommendation", "endorsement", "quality", "inbound-caller-id"])
        caller_id = next(d for d in scope["doesNotAssert"] if d["code"] == "inbound-caller-id")
        self.assertRegex(caller_id["statement"], "when you call it")
        self.assertIn(CALLER_ID, r["summary"])
        self.assertNotRegex(json.dumps(scope["asserts"]), r"(?i)\b(trusted|recommended|endorsed|rated)\b")

    def test_is_carried_by_lookups_as_the_record_states_it(self) -> None:
        found = lookup_business(registry=WORLD["registry"], domain="acme-hvac.example", fetch=FETCH, now=WORLD["now"])
        self.assertIn("license-active", [a["code"] for a in found["record"]["scope"]["asserts"]])
        legacy = lookup_business(registry=WORLD["registry"], domain="legacy-record.example", fetch=FETCH,
                                 now=WORLD["now"])
        self.assertTrue(legacy["found"])
        self.assertNotIn("scope", legacy["record"])


if __name__ == "__main__":
    unittest.main()
