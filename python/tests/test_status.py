"""R1: a status list at https://<host>/... counts only when its iss is exactly
did:web:<host> (port percent-encoded, no path), resolved through the same pinning
resolver as everything else. Anything else is "unknown". A list whose bits inflate
past 16 MiB is "unknown" too."""

from __future__ import annotations

import gzip
import unittest
import zlib

from fixtures import NOW, Key, MiniWorld, Web, b64u, did_document, status_list

from ffn_verify import DidResolver, StatusChecker, pin_registry_keys, static_txt, verify_business
from ffn_verify.pin import key_thumbprint
from ffn_verify.status import STATUS_LIST_INFLATED_MAX, inflate_status_list, status_at

INFLATED_MAX = 16 * 1024 * 1024

URI = "https://registry.test/status/1"
REG = "did:web:registry.test"
ROGUE = "did:web:registry.test:rogue"


def check(fetch: Web, uri: str = URI, *, pins: list[str] | None = None, issuer: str = REG) -> dict:
    resolver = pin_registry_keys(DidResolver(fetch=fetch), REG, pins)
    return StatusChecker(resolver=resolver, fetch=fetch, now=lambda: NOW).check(
        {"status_list": {"idx": 0, "uri": uri}}, issuer)


class StatusListSigner(unittest.TestCase):
    def test_the_inflation_cap_is_16_mib(self) -> None:
        self.assertEqual(STATUS_LIST_INFLATED_MAX, INFLATED_MAX)

    def setUp(self) -> None:
        self.a, self.r = Key(), Key()
        self.web = Web()
        self.web.json("https://registry.test/.well-known/did.json", did_document(REG, {"records-1": self.a}))
        self.web.json("https://registry.test/rogue/did.json", did_document(ROGUE, {"k": self.r}))

    def serve(self, key: Key, kid: str, iss: str, uri: str = URI, value: int = 0) -> None:
        self.web.text(uri, status_list(key, kid, iss=iss, uri=uri, values=[value, 0, 0, 0], iat=NOW),
                      "application/statuslist+jwt")

    def test_the_hosts_root_did_signs(self) -> None:
        self.serve(self.a, f"{REG}#records-1", REG)
        self.assertEqual(check(self.web)["status"], "valid")
        self.assertEqual(check(self.web, pins=[key_thumbprint(self.a.jwk)])["status"], "valid")
        self.serve(self.a, f"{REG}#records-1", REG, value=1)
        self.assertEqual(check(self.web)["status"], "invalid")

    def test_a_path_did_on_the_same_host_does_not(self) -> None:
        self.serve(self.r, f"{ROGUE}#k", ROGUE)
        self.assertEqual(check(self.web), {"status": "unknown"})
        self.assertEqual(check(self.web, pins=[key_thumbprint(self.a.jwk)]), {"status": "unknown"})
        self.assertEqual(check(self.web, issuer=ROGUE), {"status": "unknown"})  # not even for its own credentials
        self.assertNotIn("https://registry.test/rogue/did.json", self.web.log)

    def test_the_credential_issuer_on_another_host_does_not(self) -> None:
        # Stricter than before: the list's host signs it, whoever issued the credential.
        issuer, k = "did:web:issuer.example", Key()
        self.web.json("https://issuer.example/.well-known/did.json", did_document(issuer, {"k": k}))
        self.serve(k, f"{issuer}#k", issuer)
        self.assertEqual(check(self.web, issuer=issuer), {"status": "unknown"})

    def test_an_unpinned_registry_key_does_not(self) -> None:
        doc = did_document(REG, {"records-1": self.a, "records-9": self.r})
        self.web.json("https://registry.test/.well-known/did.json", doc)
        self.serve(self.r, f"{REG}#records-9", REG)
        self.assertEqual(check(self.web)["status"], "valid")  # unpinned verifier: did.json lists it
        self.assertEqual(check(self.web, pins=[key_thumbprint(self.a.jwk)]), {"status": "unknown"})

    def test_a_port_is_part_of_the_host_did(self) -> None:
        uri = "https://registry.test:8443/status/1"
        did = "did:web:registry.test%3A8443"
        self.web.json("https://registry.test:8443/.well-known/did.json", did_document(did, {"k": self.a}))
        self.serve(self.a, f"{did}#k", did, uri)
        self.assertEqual(check(self.web, uri)["status"], "valid")
        self.serve(self.a, f"{REG}#records-1", REG, uri)  # the host without its port
        self.assertEqual(check(self.web, uri), {"status": "unknown"})

    def serve_lst(self, lst: str, bits: int = 1) -> None:
        self.web.text(URI, self.a.sign({"alg": "ES256", "typ": "statuslist+jwt", "kid": f"{REG}#records-1"},
                                       {"iss": REG, "sub": URI, "iat": NOW, "exp": NOW + 86_400,
                                        "status_list": {"bits": bits, "lst": lst}}), "application/statuslist+jwt")

    def test_a_list_may_inflate_to_16_mib_and_no_further(self) -> None:
        self.serve_lst(b64u(zlib.compress(bytes(INFLATED_MAX))))
        self.assertEqual(check(self.web)["status"], "valid")
        self.serve_lst(b64u(zlib.compress(bytes(INFLATED_MAX + 1))))
        self.assertEqual(check(self.web), {"status": "unknown"})

    def test_a_bomb_stops_at_the_cap(self) -> None:
        bomb = zlib.compress(bytes(64 * 1024 * 1024), 9)  # 64 MiB of zeros in about 64 KiB
        self.assertLess(len(bomb), 2 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "past the size cap"):
            inflate_status_list(b64u(bomb))
        self.serve_lst(b64u(bomb))
        self.assertEqual(check(self.web), {"status": "unknown"})

    def test_gzip_and_malformed_lists(self) -> None:
        gz = gzip.compress(bytes([0b0100]))
        self.serve_lst(b64u(gz), bits=2)
        self.assertEqual(check(self.web)["status"], "valid")
        ref = {"status_list": {"idx": 1, "uri": URI}}
        checker = StatusChecker(resolver=DidResolver(fetch=self.web), fetch=self.web, now=lambda: NOW)
        self.assertEqual(checker.check(ref, REG)["status"], "invalid")
        good = zlib.compress(bytes(4))
        for lst, bits in ((b64u(good[:-3]), 1), (b64u(good + b"x"), 1), (b64u(b"not zlib"), 1), (b64u(good), 3),
                          (b64u(good), True), (None, 1)):
            with self.subTest(lst=lst, bits=bits):
                self.serve_lst(lst, bits)  # type: ignore[arg-type]
                self.assertEqual(check(self.web), {"status": "unknown"})

    def test_entries_are_read_in_place(self) -> None:
        raw = bytes([0b11100100, 0x00, 0x80])
        self.assertEqual([status_at(2, raw, i) for i in range(4)], [0, 1, 2, 3])
        self.assertEqual(status_at(1, raw, 23), 1)
        self.assertIsNone(status_at(1, raw, 1.5))
        with self.assertRaises(IndexError):
            status_at(8, raw, 3)

    def test_in_verify_business_a_rogue_list_fails_closed(self) -> None:
        w = MiniWorld()
        rogue_key = Key()
        w.web.json("https://registry.test/rogue/did.json", did_document(ROGUE, {"k": rogue_key}))
        w.web.text("https://registry.test/status/1",
                   status_list(rogue_key, f"{ROGUE}#k", iss=ROGUE, uri="https://registry.test/status/1",
                               values=[0] * 8, iat=NOW), "application/statuslist+jwt")
        r = verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW)
        self.assertFalse(r["verified"])
        self.assertEqual(r["failure"]["code"], "delegation_invalid")
        self.assertIn("status could not be checked", r["failure"]["message"])


if __name__ == "__main__":
    unittest.main()
