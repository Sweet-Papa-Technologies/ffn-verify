"""R2: the mainnet and devnet registry DIDs resolve only to their pinned keys, whichever
function is called; verify_presentation pins them by default and takes registry= for
a custom registry's pins."""

from __future__ import annotations

import re
import unittest
from unittest import mock

from fixtures import NOW, REPO_PASS, Key, Web, did_document, present, sd_jwt, status_list

from ffn_verify import (FFN_BUSINESS_REGISTRY, DidResolver, StatusChecker, verify_credential,
                        verify_presentation)
from ffn_verify.networks import DEVNET_REGISTRY_KEYS, FFN_DEVNET_BUSINESS_REGISTRY, KNOWN_REGISTRY_KEYS
from ffn_verify.pin import key_thumbprint

MAINNET = "did:web:registry.fofo.network"
DEVNET = "did:web:fofo-registry-devnet.web.app"
AUD, NONCE = "https://agent.example", "n-1"


def host_of(did: str) -> str:
    return did[len("did:web:"):]


class Issued:
    """A credential the registry DID ``did`` issues to a did:jwk holder, signed by a key
    that the served did.json lists (but nobody pins)."""

    def __init__(self, did: str, key: Key | None = None):
        self.did, self.key, self.holder = did, key or Key(), Key()
        self.web = Web()
        self.web.json(f"https://{host_of(did)}/.well-known/did.json", did_document(did, {"records-1": self.key}))
        self.compact = sd_jwt(self.key, f"{did}#records-1", {
            "iss": did, "sub": self.holder.did_jwk, "vct": "https://pass.fofo.network/vct/business-identity/v1",
            "iat": NOW - 60, "exp": NOW + 3600, "cnf": {"jwk": self.holder.jwk}})
        self.presentation = present(self.compact, self.holder, audience=AUD, nonce=NONCE, iat=NOW)

    def verify(self, **options: object) -> dict:
        return verify_presentation({"presentation": self.presentation, "nonce": NONCE, "audience": AUD,
                                    "issuers": [self.did]}, fetch=self.web, now=NOW, **options)


class KnownRegistries(unittest.TestCase):
    def test_both_networks_are_known(self) -> None:
        self.assertEqual(KNOWN_REGISTRY_KEYS[MAINNET], tuple(FFN_BUSINESS_REGISTRY["keyThumbprints"]))
        self.assertEqual(KNOWN_REGISTRY_KEYS[DEVNET], DEVNET_REGISTRY_KEYS)
        self.assertEqual(FFN_DEVNET_BUSINESS_REGISTRY["did"], DEVNET)

    def test_a_did_resolver_keeps_only_pinned_keys(self) -> None:
        for did in (MAINNET, DEVNET):
            with self.subTest(did=did):
                issued = Issued(did)
                resolver = DidResolver(fetch=issued.web)
                self.assertEqual(resolver.resolve(did)["verificationMethod"], [])
                with self.assertRaisesRegex(ValueError, "not one of the registry keys this verifier pins"):
                    resolver.assertion_key(did, f"{did}#records-1")
                self.assertFalse(resolver.controls_key(did, issued.key.jwk))

    def test_pre_resolved_documents_are_pinned_too(self) -> None:
        issued = Issued(MAINNET)
        doc = did_document(MAINNET, {"records-1": issued.key})
        resolver = DidResolver(fetch=Web(), documents={MAINNET: doc})
        self.assertEqual(resolver.resolve(MAINNET)["verificationMethod"], [])

    def test_verify_presentation_pins_them_by_default(self) -> None:
        for did in (MAINNET, DEVNET):
            with self.subTest(did=did):
                r = Issued(did).verify()
                self.assertFalse(r["verified"])
                self.assertEqual(r["code"], "untrusted_issuer")
                self.assertIn("pins", r["message"])

    def test_a_caller_resolver_of_its_own_is_pinned_too(self) -> None:
        issued = Issued(MAINNET)
        inner = DidResolver(fetch=issued.web)

        class Duck:  # not a DidResolver
            def resolve(self, did: str) -> dict:
                return inner._document(did)

            def assertion_key(self, did, kid):  # type: ignore[no-untyped-def]
                raise AssertionError("not used")

        r = issued.verify(resolver=Duck())
        self.assertEqual((r["verified"], r.get("code")), (False, "untrusted_issuer"), r.get("message"))
        self.assertIn("no unique assertionMethod key", r["message"])

    def test_verify_credential_and_status_lists_with_a_plain_resolver(self) -> None:
        issued = Issued(MAINNET)
        with self.assertRaisesRegex(Exception, "pins"):
            verify_credential(issued.compact, resolver=DidResolver(fetch=issued.web), now=NOW)
        uri = "https://registry.fofo.network/status/1"
        issued.web.text(uri, status_list(issued.key, f"{MAINNET}#records-1", iss=MAINNET, uri=uri, values=[0],
                                         iat=NOW), "application/statuslist+jwt")
        checker = StatusChecker(resolver=DidResolver(fetch=issued.web), fetch=issued.web, now=lambda: NOW)
        self.assertEqual(checker.check({"status_list": {"idx": 0, "uri": uri}}, MAINNET), {"status": "unknown"})

    def test_a_pinned_key_still_verifies(self) -> None:
        issued = Issued(MAINNET)
        pins = {MAINNET: (key_thumbprint(issued.key.jwk),)}
        with mock.patch("ffn_verify.did.KNOWN_REGISTRY_KEYS", pins), \
                mock.patch("ffn_verify.pin.KNOWN_REGISTRY_KEYS", pins):
            r = issued.verify()
            self.assertTrue(r["verified"], r.get("message"))
            self.assertTrue(issued.verify(registry=FFN_BUSINESS_REGISTRY | {"keyThumbprints": None})["verified"])
            # Explicit pins narrow further; they never widen past the known ones.
            self.assertFalse(issued.verify(registry={**FFN_BUSINESS_REGISTRY, "keyThumbprints": ["other"]})["verified"])


class CustomRegistry(unittest.TestCase):
    def test_registry_pins_a_custom_registry(self) -> None:
        issued = Issued("did:web:registry.test")
        self.assertTrue(issued.verify()["verified"])  # unpinned custom registry: did.json decides
        anchor = {"origin": "https://registry.test", "did": "did:web:registry.test"}
        self.assertTrue(issued.verify(registry={**anchor, "keyThumbprints": [key_thumbprint(issued.key.jwk)]})[
            "verified"])
        r = issued.verify(registry={**anchor, "keyThumbprints": [key_thumbprint(Key().jwk)]})
        self.assertFalse(r["verified"])
        self.assertIn("not one of the registry keys this verifier pins", r["message"])

    def test_registry_does_not_add_to_the_accepted_issuers(self) -> None:
        issued = Issued("did:web:registry.test")
        r = verify_presentation({"presentation": issued.presentation, "nonce": NONCE, "audience": AUD},
                                fetch=issued.web, now=NOW,
                                registry={"origin": "https://registry.test", "did": "did:web:registry.test"})
        self.assertEqual(r["code"], "untrusted_issuer")


@unittest.skipUnless((REPO_PASS / "packages" / "door-core" / "src" / "networks.ts").is_file(),
                     "the TypeScript sources are not here")
class SameAsTypeScript(unittest.TestCase):
    def test_pins_match_networks_ts(self) -> None:
        ts = (REPO_PASS / "packages" / "door-core" / "src" / "networks.ts").read_text("utf-8")
        for name, keys in (("PRODUCTION_REGISTRY_KEYS", FFN_BUSINESS_REGISTRY["keyThumbprints"]),
                           ("DEVNET_REGISTRY_KEYS", list(DEVNET_REGISTRY_KEYS))):
            block = re.search(rf"const {name} = \[(.*?)\];", ts, re.S).group(1)
            self.assertEqual(keys, re.findall(r"^\s*'([A-Za-z0-9_-]+)',", block, re.M), name)
        self.assertIn("'fofo-registry-devnet.web.app'", ts)


if __name__ == "__main__":
    unittest.main()
