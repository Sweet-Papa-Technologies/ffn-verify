"""R3: trust is decided before anything is fetched. A presentation from an issuer the
caller doesn't accept, or a delegation chain rooted at a DID the caller doesn't accept,
fails with zero requests; a link's status list is fetched only after its signature
verified."""

from __future__ import annotations

import unittest

from fixtures import NOW, Key, Web, did_document, present, sd_jwt, status_list

from ffn_verify import DidResolver, StatusChecker, verify_delegation_chain, verify_presentation
from ffn_verify.business import BUSINESS_KINDS
from ffn_verify.credential import CredentialError, credential_hash

AUD, NONCE = "https://agent.example", "n-1"
INTERNAL = "https://10.0.0.5:8443/admin/reset?all=1"
BIZ = "did:web:acme.example"
STATUS = "https://acme.example/status/1"


def delegation(signer: Key, kid: str, iss: str, holder: Key, *, sub: str | None = None,
               status_uri: str | None = None, parent: str | None = None, scope: list[str] | None = None) -> str:
    return sd_jwt(signer, kid, {
        "iss": iss, "sub": sub or holder.did_jwk, "vct": BUSINESS_KINDS["delegation"], "iat": NOW - 60,
        "exp": NOW + 3600, "jti": f"d-{iss}", "cnf": {"jwk": holder.jwk}, "scope": scope or ["booking:create"],
        "delegateKind": "agent",
        **({"status": {"status_list": {"idx": 0, "uri": status_uri}}} if status_uri else {}),
        **({"parent": credential_hash(parent)} if parent else {})})


class Presentations(unittest.TestCase):
    def setUp(self) -> None:
        self.attacker, self.holder = Key(), Key()
        self.web = Web()  # every request is logged; most tests expect none

    def run_presentation(self, presentation: str, **input: object) -> dict:
        return verify_presentation({"presentation": presentation, "nonce": NONCE, "audience": AUD, **input},
                                   fetch=self.web, now=NOW)

    def test_an_unaccepted_issuer_fails_without_a_request(self) -> None:
        for iss in ("did:web:attacker.example", "did:web:10.0.0.9%3A9443:internal:svc"):
            cred = sd_jwt(self.attacker, f"{iss}#k1", {
                "iss": iss, "sub": self.holder.did_jwk, "vct": "https://x/vct", "iat": NOW, "exp": NOW + 60,
                "cnf": {"jwk": self.holder.jwk}, "status": {"status_list": {"idx": 0, "uri": INTERNAL}}})
            p = present(cred, self.holder, audience=AUD, nonce=NONCE, iat=NOW)
            for issuers in (["did:web:registry.fofo.network"], None, []):
                with self.subTest(iss=iss, issuers=issuers):
                    r = self.run_presentation(p, **({} if issuers is None else {"issuers": issuers}))
                    self.assertEqual((r["verified"], r["code"]), (False, "untrusted_issuer"))
                    self.assertEqual(self.web.log, [])

    def test_a_delegation_rooted_at_an_unaccepted_did_fails_without_a_request(self) -> None:
        iss = "did:web:attacker.example"
        d = delegation(self.attacker, f"{iss}#k1", iss, self.holder, status_uri=INTERNAL, scope=["anything"])
        p = present(d, self.holder, audience=AUD, nonce=NONCE, iat=NOW)
        for roots in (["did:web:registry.fofo.network"], None, []):
            with self.subTest(roots=roots):
                r = self.run_presentation(p, **({} if roots is None else {"roots": roots}))
                self.assertEqual((r["verified"], r["code"]), (False, "untrusted_root"))
                self.assertEqual(self.web.log, [])

    def test_a_longer_chain_is_judged_by_its_root_link(self) -> None:
        agent, root_key = Key(), Key()
        root = delegation(root_key, "did:web:attacker.example#k1", "did:web:attacker.example", agent,
                          status_uri=INTERNAL, scope=["booking:*"])
        leaf = delegation(agent, "", agent.did_jwk, self.holder, parent=root)
        p = present(leaf, self.holder, audience=AUD, nonce=NONCE, iat=NOW)
        r = self.run_presentation(p, chain=[root], roots=[BIZ])
        self.assertEqual((r["verified"], r["code"]), (False, "untrusted_root"))
        self.assertIn("the chain starts at did:web:attacker.example", r["message"])
        self.assertEqual(self.web.log, [])

    def test_an_accepted_root_is_resolved_then_its_status_fetched(self) -> None:
        biz = Key()
        self.web.json("https://acme.example/.well-known/did.json", did_document(BIZ, {"key-1": biz}))
        self.web.text(STATUS, status_list(biz, f"{BIZ}#key-1", iss=BIZ, uri=STATUS, values=[0], iat=NOW),
                      "application/statuslist+jwt")
        d = delegation(biz, f"{BIZ}#key-1", BIZ, self.holder, status_uri=STATUS)
        r = self.run_presentation(present(d, self.holder, audience=AUD, nonce=NONCE, iat=NOW), roots=[BIZ])
        self.assertTrue(r["verified"], r.get("message"))
        self.assertEqual(r["delegation"]["root"], BIZ)
        self.assertEqual(self.web.log[0], "https://acme.example/.well-known/did.json")
        self.assertIn(STATUS, self.web.log)

    def test_a_link_whose_signature_fails_never_has_its_status_fetched(self) -> None:
        biz, impostor = Key(), Key()
        self.web.json("https://acme.example/.well-known/did.json", did_document(BIZ, {"key-1": biz}))
        d = delegation(impostor, f"{BIZ}#key-1", BIZ, self.holder, status_uri=STATUS)
        r = self.run_presentation(present(d, self.holder, audience=AUD, nonce=NONCE, iat=NOW), roots=[BIZ])
        self.assertFalse(r["verified"])
        self.assertNotIn(STATUS, self.web.log)


class Chains(unittest.TestCase):
    def test_verify_delegation_chain_checks_roots_before_resolving(self) -> None:
        web, attacker, holder = Web(), Key(), Key()
        d = delegation(attacker, "did:web:attacker.example#k1", "did:web:attacker.example", holder,
                       status_uri=INTERNAL)
        resolver = DidResolver(fetch=web)
        with self.assertRaises(CredentialError) as caught:
            verify_delegation_chain([d], resolver=resolver, now=NOW, roots=[BIZ],
                                    status=StatusChecker(resolver=resolver, fetch=web, now=lambda: NOW))
        self.assertEqual(caught.exception.code, "untrusted_root")
        self.assertEqual(web.log, [])

    def test_an_undecodable_chain_is_malformed(self) -> None:
        web = Web()
        resolver = DidResolver(fetch=web)
        with self.assertRaisesRegex(CredentialError, "malformed credential"):
            verify_delegation_chain(["not-a-jwt~"], resolver=resolver, now=NOW, roots=[BIZ],
                                    status=StatusChecker(resolver=resolver, fetch=web, now=lambda: NOW))
        self.assertEqual(web.log, [])


if __name__ == "__main__":
    unittest.main()
