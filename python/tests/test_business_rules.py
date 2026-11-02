"""R5 observedMatches, R6 phone queries and R7 robustness, on a world signed here
(and on the shared vectors when they are present)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from fixtures import NO_VECTORS, NOW, REGISTRY_ORIGIN, MiniWorld, did_document, load_world, world_fetch

from ffn_verify import DidResolver, lookup_business, static_txt, verify_business

WORLD = load_world()


def run(w: MiniWorld, domain: str | None = None, **kw: object) -> dict:
    """verify_business on the mini world; by its domain unless a domain or phone is given."""
    if domain is None and "phone" not in kw:
        domain = w.domain
    return verify_business(domain, registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW, **kw)


class ObservedMatches(unittest.TestCase):
    def test_present_on_every_result(self) -> None:
        w = MiniWorld()
        self.assertIs(run(w)["observedMatches"], True)
        self.assertIs(run(w, "missing.example")["observedMatches"], True)  # failed: nothing was compared
        self.assertIs(run(w, "not a domain")["observedMatches"], True)
        self.assertIs(run(w, phone="12")["observedMatches"], True)

    def test_false_when_what_the_agent_sees_does_not_match(self) -> None:
        w = MiniWorld()
        for observed in ({"name": "Other Co"}, {"phone": "(415) 555-0199"}, {"phone": "not a phone"}):
            with self.subTest(observed=observed):
                r = run(w, observed=observed)
                self.assertTrue(r["verified"], r["summary"])  # the record still verified
                self.assertIs(r["observedMatches"], False)
                self.assertEqual(len(r["mismatches"]), 1)
        r = run(w, observed={"name": "BIZ INC", "phone": "+1 415 555 0100"})
        self.assertEqual((r["verified"], r["observedMatches"]), (True, True))

    def test_the_key_sits_after_mismatches(self) -> None:
        keys = list(run(MiniWorld()))
        self.assertEqual(keys[keys.index("mismatches") + 1], "observedMatches")

    @unittest.skipUnless(WORLD, NO_VECTORS)
    def test_on_the_vector_world(self) -> None:
        observed = {"name": "ACME HVAC, Inc.", "phone": "(415) 555-0199", "address": "12 Main St, Oakland, CA 94607"}
        r = verify_business("acme-hvac.example", registry=WORLD["registry"], fetch=world_fetch(WORLD),
                            dns=static_txt(WORLD["dns"]), now=WORLD["now"], observed=observed)
        self.assertEqual((r["verified"], r["observedMatches"], len(r["mismatches"])), (True, False, 1))


class PhoneQueries(unittest.TestCase):
    def test_a_confirmed_phone_verifies_its_business(self) -> None:
        w = MiniWorld()
        r = run(w, phone="(415) 555-0100")
        self.assertTrue(r["verified"], r["summary"])
        self.assertEqual((r["phone"], r["domain"], r["level"]), ("+14155550100", "biz.example", 1))
        self.assertEqual(list(r)[:3], ["verified", "domain", "phone"])
        self.assertTrue(r["summary"].startswith("+14155550100 (biz.example) belongs to Biz Inc., listed"))
        self.assertIn(f"{REGISTRY_ORIGIN}/v1/lookup?phone=%2B14155550100", w.web.log)

    def test_an_unconfirmed_phone_does_not_count_official_channels(self) -> None:
        w = MiniWorld(record_phones=("+14155550100", "+14155550199"), oc_phones=("+14155550100",))
        r = run(w, phone="+1 415 555 0199")
        self.assertFalse(r["verified"])
        self.assertEqual((r["level"], r["failure"]["code"]), (0, "not_verified"))
        self.assertIn("+14155550199 is not among the phone numbers SPT confirmed.", r["warnings"])
        self.assertEqual(next(f for f in r["facts"] if f["kind"] == "officialChannels")["status"], "valid")
        self.assertTrue(r["summary"].startswith("+14155550199 (biz.example) belongs to Biz Inc., but no current"))
        self.assertTrue(run(w, phone="+14155550100")["verified"])  # the confirmed one still does
        self.assertTrue(run(w, "biz.example")["verified"])  # and so does the domain

    def test_failures(self) -> None:
        w = MiniWorld()
        r = run(w, phone="12")
        self.assertEqual((r["failure"]["code"], r["phone"], r["domain"]), ("bad_phone", "12", ""))
        self.assertTrue(r["summary"].startswith("12 could not be verified: "))
        r = run(w, phone="+14155550111")
        self.assertEqual(r["failure"], {"code": "not_in_registry", "message": "+14155550111 is not in the registry"})
        self.assertTrue(r["summary"].startswith("+14155550111 could not be verified"))
        # The registry answers with a record that doesn't list the number asked about.
        w.web.routes[f"{REGISTRY_ORIGIN}/v1/lookup?phone=%2B14155550111"] = \
            w.web.routes[f"{REGISTRY_ORIGIN}/v1/lookup?phone=%2B14155550100"]
        r = run(w, phone="+14155550111")
        self.assertEqual(r["failure"]["code"], "phone_not_listed")

    def test_the_primary_domain_is_the_profile_pages(self) -> None:
        w = MiniWorld()
        w.record_payload["domains"] = ["other.example", "biz.example"]
        w.publish()
        self.assertEqual(run(w, phone="+14155550100")["domain"], "biz.example")
        w.record_payload["profileUrl"] = f"{REGISTRY_ORIGIN}/b/rec-1"
        w.publish()
        self.assertEqual(run(w, phone="+14155550100")["domain"], "other.example")  # else the first listed

    def test_exactly_one_of_domain_and_phone(self) -> None:
        w = MiniWorld()
        with self.assertRaises(TypeError):
            verify_business(registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW)
        with self.assertRaises(TypeError):
            run(w, "biz.example", phone="+14155550100")
        self.assertTrue(verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns),
                                        now=NOW)["verified"])
        self.assertNotIn("phone", run(w, "biz.example"))

    def test_lookup_by_phone(self) -> None:
        w = MiniWorld()
        found = lookup_business(registry=w.registry, phone="415-555-0100", fetch=w.web, now=NOW)
        self.assertEqual(found["record"]["domains"], ["biz.example"])

    @unittest.skipUnless(WORLD, NO_VECTORS)
    def test_on_the_vector_world(self) -> None:
        r = verify_business(phone="(415) 555-0100", registry=WORLD["registry"], fetch=world_fetch(WORLD),
                            dns=static_txt(WORLD["dns"]), now=WORLD["now"])
        self.assertEqual((r["verified"], r["level"], r["domain"], r["phone"]),
                         (True, 2, "acme-hvac.example", "+14155550100"), r["summary"])


class Robustness(unittest.TestCase):
    DOC_URL = "https://biz.example/.well-known/did.json"

    def test_a_service_that_is_not_an_array_binds_nothing(self) -> None:
        for service in ({"type": "FfnVerifiedBusiness", "serviceEndpoint": "https://registry.test/v1/businesses/rec-1"},
                        "FfnVerifiedBusiness", 7, None, True):
            with self.subTest(service=service):
                r = run(MiniWorld(doc_extra={"service": service}))
                self.assertEqual((r["binding"]["status"], r["failure"]["code"]), ("missing", "binding_failed"))

    def test_service_entries_that_are_not_objects_are_skipped(self) -> None:
        w = MiniWorld()
        doc = json.loads(w.web.routes[self.DOC_URL][2])
        doc["service"] = [None, 3, "x", [], *doc["service"]]
        w.web.json(self.DOC_URL, doc)
        self.assertEqual(run(w)["binding"]["status"], "confirmed")

    def test_also_known_as_that_is_not_an_array_binds_nothing(self) -> None:
        w = MiniWorld()
        w.record_payload["domains"] = ["biz.example", "alias.example"]
        w.publish()
        w.dns["_ffn.alias.example"] = w.dns["_ffn.biz.example"]
        alias = "https://alias.example/.well-known/did.json"
        service = [{"id": "did:web:alias.example#ffn", "type": "FfnVerifiedBusiness",
                    "serviceEndpoint": f"{REGISTRY_ORIGIN}/v1/businesses/rec-1"}]
        for also in (["did:web:biz.example"], "did:web:biz.example", "xx did:web:biz.example xx",
                     {"0": "did:web:biz.example"}, None):
            with self.subTest(alsoKnownAs=also):
                w.web.json(alias, did_document("did:web:alias.example", {}, alsoKnownAs=also, service=service))
                r = run(w, "alias.example")
                want = "confirmed" if isinstance(also, list) else "missing"
                self.assertEqual(r["binding"]["status"], want, r["summary"])
        # On the primary document too: a malformed alsoKnownAs is a malformed document.
        r = run(MiniWorld(doc_extra={"alsoKnownAs": "did:web:biz.example"}))
        self.assertEqual(r["binding"]["status"], "missing")

    def test_odd_documents_never_raise(self) -> None:
        for extra in ({"verificationMethod": "x"}, {"verificationMethod": {"a": 1}}, {"assertionMethod": 5},
                      {"authentication": None, "assertionMethod": None}):
            with self.subTest(extra=extra):
                r = run(MiniWorld(doc_extra=extra))
                self.assertFalse(r["verified"])
        w = MiniWorld()
        for body in (b"[]", b'"x"', b"null", b"{}", b"{"):
            with self.subTest(body=body):
                w.web.routes[self.DOC_URL] = (200, "application/json", body)
                self.assertIn(run(w)["binding"]["status"], ("missing", "unreachable"))

    def test_a_cached_document_stands_in_for_at_most_a_day(self) -> None:
        w = MiniWorld()
        doc = w.web.routes[self.DOC_URL]
        clock = [1_000_000.0]
        with mock.patch("ffn_verify.did.time.time", lambda: clock[0]):
            resolver = DidResolver(fetch=w.web, ttl_seconds=300)
            self.assertEqual(resolver.resolve("did:web:biz.example")["id"], "did:web:biz.example")
            w.web.routes[self.DOC_URL] = ConnectionError("down")
            clock[0] += 300 + 86_400 - 1  # past its ttl, within a day of it
            self.assertEqual(resolver.resolve("did:web:biz.example")["id"], "did:web:biz.example")
            clock[0] += 2  # more than a day past its ttl
            with self.assertRaisesRegex(ValueError, "could not resolve"):
                resolver.resolve("did:web:biz.example")
            w.web.routes[self.DOC_URL] = doc
            self.assertEqual(resolver.resolve("did:web:biz.example")["id"], "did:web:biz.example")
        self.assertEqual(DidResolver(max_stale_seconds=0)._max_stale, 0)


if __name__ == "__main__":
    unittest.main()
