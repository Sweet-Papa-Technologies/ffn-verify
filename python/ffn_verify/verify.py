"""verify_business(domain): the wallet-free public verifier (plan, "How an agent verifies").

  1. Ask the registry the agent already knows, by domain. Never a registry URL the
     site supplies: a page saying it is verified is only a claim.
  2. Check the registry's signature on the record, the business's signature on its
     profile and delegation, and SPT's signature on each attestation, then each
     one's status.
  3. Confirm the domain binding: the DID document and DNS record on the domain point
     back to this registry entry. A lookalike fails here.
  4. Compare what the agent sees (name, phone, address) against the record.
  5. Report what was verified and when, in plain words.

A port of verify-business/src/verify.ts. Results use the TS JSON shape (camelCase
keys; optional keys are left out rather than set to None).
"""

from __future__ import annotations

import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, MutableMapping

from ._egress import check_registry_origin
from ._js import array, includes, is_num, iso, iterable, js_str, nullish, opt, prop, template, trim, truthy, utf16_key
from ._js import join as js_join
from .binding import ffn_txt_name, parse_ffn_txt, registry_entries_of
from .business import (ATTESTATION_KINDS, BUSINESS_KINDS, BUSINESS_RECORD_TYP, KIND_LABELS, LEVEL_NAMES,
                       REGISTRY_SCOPES, kind_for_vct, level_for)
from .credential import CredentialError, same_key, verify_credential
from .delegation import verify_delegation_chain
from .did import DidResolver, did_web_host, is_did_jwk, jwk_of_did_jwk
from .dns import TxtResolver, doh_resolver
from .domain import name_key, normalize_domain, normalize_phone
from .fetch import (DEFAULT_TIMEOUT, REGISTRY_RESPONSE_MAX, Fetch, FetchTimeout, ResponseTooLarge, bounded_fetch, ok,
                    text_of, urllib_fetch)
from .jose import decode_jwt, header_kid, verify_jwt
from .pin import anchored_resolver, registry_did_of
from .status import StatusChecker
from .url import URL


class VerificationError(Exception):
    """A verification that stopped with a failure code (the TS's Stop). lookup_business
    raises it; verify_business reports it as ``failure``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# Claims that are JWT structure or evidence, not attested facts.
STRUCTURAL = {"iss", "iat", "nbf", "exp", "sub", "jti", "vct", "cnf", "status", "_sd_alg", "evidence"}
PROFILE_FIELDS = ("name", "dba", "domains", "phones", "hours", "address", "serviceArea", "categories")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _date(value: Any) -> datetime | None:
    """new Date(value), for the ISO strings and epoch milliseconds the TS passes it."""
    try:
        if is_num(value):
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _day(value: Any) -> str:
    """e.g. "Jan 31, 2027", as toLocaleDateString('en-US', {month: 'short', ..., timeZone: 'UTC'})."""
    if not truthy(value):
        return "an unknown date"
    if isinstance(value, str) and len(value) == 10:
        value = f"{value}T00:00:00Z"
    d = _date(value)
    return f"{MONTHS[d.month - 1]} {d.day}, {d.year}" if d else "Invalid Date"


def _last_checked(checks: Any) -> Any:
    passed = [c["checkedAt"] for c in array(checks, "checks")
              if prop(c, "result") == "pass" and truthy(prop(c, "checkedAt"))]
    return sorted(passed, key=utf16_key)[-1] if passed else None


def _sentence_for(kind: str, c: dict, checks: Any) -> str:
    when = f"checked {_day(_last_checked(checks))}"
    if kind == "businessIdentity":
        entity_type = f"{js_str(c['entityType'])} " if truthy(c.get("entityType")) else ""
        return (f"{template(c, 'legalName')} is an active {entity_type}entity in {template(c, 'jurisdiction')}, "
                f"number {template(c, 'entityNumber')} ({when}).")
    if kind == "officialChannels":
        controls = [*iterable(nullish(c.get("domains"), []), "domains"),
                    *iterable(nullish(c.get("phones"), []), "phones")]
        return f"It controls {js_join(controls, ', ')} ({when})."
    if kind == "license":
        classes = js_join([prop(k, "code") for k in array(nullish(c.get("classes"), []), "classes")], ", ")
        return (f"{template(c, 'board')} license {template(c, 'licenseNumber')}{f' ({classes})' if classes else ''} "
                f"is active until {_day(c.get('expiresOn'))} ({when}).")
    if kind == "insurance":
        coverage = template(c, "coverageType").replace("-", " ")
        coverage = coverage[:1].upper() + coverage[1:]
        return f"{coverage} insurance with {template(c, 'carrier')} runs until {_day(c.get('expiresOn'))} ({when})."
    role = template(c, "role").replace("-", " ")
    return f"A person verified with an FFN person pass is authorized to act for it as {role} ({when})."


def _form_value(value: str) -> str:
    # URLSearchParams: like quote_plus, but * stays and ~ is escaped.
    return urllib.parse.quote_plus(value, safe="*").replace("~", "%7E")


def _fetch_record(origin: str, query: dict, fetch: Fetch, timeout: float) -> str | None:
    """Fetch the record for a domain or phone from the pinned registry (at most 1 MiB)."""
    key = "domain" if truthy(query.get("domain")) else "phone"
    base = origin[:-1] if origin.endswith("/") else origin
    try:
        status, _, body = bounded_fetch(fetch, f"{base}/v1/lookup?{key}={_form_value(query[key])}",
                                        {"accept": "application/ffn-business-record+jwt"},
                                        max_bytes=REGISTRY_RESPONSE_MAX, timeout=timeout)
    except FetchTimeout:
        raise VerificationError("registry_unavailable", "the registry did not answer in time") from None
    except ResponseTooLarge:
        raise VerificationError("registry_unavailable", "the registry's answer was too large") from None
    except Exception:
        raise VerificationError("registry_unavailable", "the registry could not be reached") from None
    if status == 404:
        return None
    if not ok(status):
        raise VerificationError("registry_unavailable", f"the registry answered HTTP {status}")
    return trim(text_of(body))


def _open_record(jwt: str, registry_did: str, resolver: DidResolver, now: float) -> dict:
    """Verify the registry's signature on a record."""
    try:
        header = decode_jwt(jwt)[0]
    except Exception:
        raise VerificationError("bad_record", "the registry record is malformed") from None
    try:
        key = resolver.assertion_key(registry_did, header_kid(header))
    except Exception as err:
        raise VerificationError("bad_record", f"the registry key could not be resolved: {err}") from None
    try:
        _, payload = verify_jwt(jwt, key, typ=BUSINESS_RECORD_TYP, now=now)
        if prop(payload, "iss") != registry_did:
            raise ValueError("issued by someone else")
        return payload
    except Exception as err:
        raise VerificationError("bad_record", f"the registry record failed verification: {err}") from None


def lookup_business(*, registry: dict, domain: str | None = None, phone: str | None = None,
                    fetch: Fetch | None = None, resolver: DidResolver | None = None,
                    now: float | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Look a business up by domain or phone. Only the registry's signature is checked:
    binding, profile and attestation signatures are not, so call verify_business.

    Returns {found: False} or {found: True, record: {sub, recordId, domains, phones, level,
    profileUrl, updatedAt, name?}}. Raises VerificationError or IdentifierError, and
    ValueError when the registry origin isn't https (plain http only on a loopback host).
    """
    check_registry_origin(registry["origin"])
    fetch = fetch or urllib_fetch
    registry_did = registry_did_of(registry)
    resolver = anchored_resolver(resolver or DidResolver(fetch=fetch, timeout=timeout), registry)
    query = {"domain": normalize_domain(domain)} if truthy(domain) else {"phone": normalize_phone(nullish(phone, ""))}
    jwt = _fetch_record(registry["origin"], query, fetch, timeout)
    if not truthy(jwt):
        return {"found": False}
    rec = _open_record(jwt, registry_did, resolver, int(time.time()) if now is None else now)
    # A record that doesn't list what was asked for is not an answer to the question.
    asked, listed = (query["domain"], rec.get("domains")) if "domain" in query else (query["phone"], rec.get("phones"))
    if not includes(listed, asked):
        return {"found": False}
    fields = ("sub", "recordId", "domains", "phones", "level", "profileUrl", "updatedAt")
    record = {k: rec[k] for k in fields if k in rec}
    try:
        name = prop(decode_jwt(rec["profile"].split("~")[0])[1], "name")
        if truthy(name):
            record["name"] = name
    except Exception:
        pass  # reported without a name
    if _is_scope(rec.get("scope")):
        record["scope"] = rec["scope"]  # as the record states it, not yet checked
    return {"found": True, "record": record}


def _primary_domain(record: dict) -> str:
    """The domain a record answers for by default: its profile page's, else the first it lists."""
    profile_url = record.get("profileUrl")
    if not isinstance(profile_url, str):
        raise TypeError("profileUrl.split is not a function")
    from_profile = profile_url.split("/")[-1]
    domains = array(record.get("domains"), "domains")
    if includes(domains, from_profile):
        return from_profile
    if not domains or not isinstance(domains[0], str):
        raise VerificationError("domain_not_listed", "the record lists no domain")
    return domains[0]


def verify_business(domain: str | None = None, *, phone: str | None = None, registry: dict,
                    fetch: Fetch | None = None, dns: TxtResolver | None = None,
                    resolver: DidResolver | None = None, store: MutableMapping[str, dict] | None = None,
                    now: float | None = None, observed: dict | None = None,
                    timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Verify the business behind ``domain``, or behind the phone number it published
    (``verify_business(phone="+14155550100", registry=...)``), against the pinned
    ``registry`` ({origin, did?, name?, keyThumbprints?}; FFN_BUSINESS_REGISTRY is the
    production one). Give exactly one of the two. ``observed`` is what the agent sees:
    {name?, phone?, address?}. ``timeout`` is the total time limit, in seconds, for each
    request the verification makes.

    Returns {verified, domain, phone?, level, levelName, business?, facts, binding,
    delegation, scope?, mismatches, observedMatches, warnings, failure?, summary,
    checkedAt}. ``verified`` says the record and its checks verified; ``observedMatches``
    says what the agent sees matches it (no mismatches). Check both. For a phone query,
    ``domain`` is the business's primary domain and the binding is checked there; the
    phone counts only when SPT's official channels attestation confirms it.

    Raises TypeError unless exactly one of domain and phone is given, and ValueError
    when the registry origin isn't https (plain http only on a loopback host).
    """
    if (domain is None) == (phone is None):
        raise TypeError("verify_business needs a domain or a phone number, not both")
    check_registry_origin(registry["origin"])
    fetch = fetch or urllib_fetch
    registry_did = registry_did_of(registry)
    resolver = anchored_resolver(resolver or DidResolver(fetch=fetch, ttl_seconds=300, timeout=timeout), registry)
    now_sec = int(time.time()) if now is None else now
    status = StatusChecker(resolver=resolver, fetch=fetch, store=store, now=lambda: now_sec, timeout=timeout)
    dns = dns or doh_resolver("cloudflare", fetch, timeout=timeout)
    registry_host = URL(registry["origin"]).host
    registry_name = nullish(registry.get("name"), "The registry")

    out: dict[str, Any] = {
        "verified": False,
        "domain": domain if phone is None else "",
        **({"phone": phone} if phone is not None else {}),
        "level": 0,
        "levelName": LEVEL_NAMES[0],
        "facts": [],
        "binding": {"status": "missing", "didDocument": False, "dnsTxt": False, "lowerAssurance": False},
        "delegation": {"valid": False},
        "mismatches": [],
        "observedMatches": True,
        "warnings": [],
        "summary": "",
        "checkedAt": iso(now_sec),
    }

    try:
        asked_phone = None
        if phone is not None:
            try:
                asked_phone = normalize_phone(phone)
            except Exception as err:
                raise VerificationError("bad_phone", str(err)) from None
            out["phone"] = asked_phone
            # 1-2. The record, from the registry we already trust; then its domain, as for a domain query.
            jwt = _fetch_record(registry["origin"], {"phone": asked_phone}, fetch, timeout)
            if not truthy(jwt):
                raise VerificationError("not_in_registry", f"{asked_phone} is not in the registry")
            record = _open_record(jwt, registry_did, resolver, now_sec)
            if not includes(record.get("phones"), asked_phone):
                raise VerificationError("phone_not_listed", f"the record does not list {asked_phone}")
            name = _primary_domain(record)
            out["domain"] = name
        else:
            try:
                name = normalize_domain(domain)
            except Exception as err:
                raise VerificationError("bad_domain", str(err)) from None
            out["domain"] = name

            # 1-2. The record, from the registry we already trust.
            jwt = _fetch_record(registry["origin"], {"domain": name}, fetch, timeout)
            if not truthy(jwt):
                raise VerificationError("not_in_registry", f"{name} is not in the registry")
            record = _open_record(jwt, registry_did, resolver, now_sec)
            if not includes(record.get("domains"), name):
                raise VerificationError("domain_not_listed", f"the record does not list {name}")
        did = record.get("sub")

        # 3. The domain binding, first: it fetches the DID document the signatures below need,
        # so a site that is down reads as "can't check right now", not as a bad signature.
        out["binding"] = _check_binding(name, did, record.get("recordId"), registry_host, resolver, dns,
                                        out["warnings"])
        if out["binding"]["status"] in ("mismatch", "missing"):
            raise VerificationError("binding_failed", f"{name} does not point back to this registry entry")
        if out["binding"]["status"] == "unreachable":
            raise VerificationError("binding_unreachable", f"the binding on {name} could not be checked right now")

        # The business's own signature on its profile.
        try:
            v = verify_credential(record.get("profile"), resolver=resolver, now=now_sec)
            if v["iss"] != did or v["vct"] != BUSINESS_KINDS["businessProfile"]:
                raise ValueError("not this business’s profile")
            profile = v["claims"]
        except Exception as err:
            raise VerificationError("bad_profile", f"the business profile failed verification: {err}") from None
        out["business"] = {
            "did": did,
            **{k: record[k] for k in ("recordId", "profileUrl") if k in record},
            **{k: profile[k] for k in PROFILE_FIELDS if k in profile},
        }
        if profile.get("domains") is None or not includes(profile["domains"], name):
            out["warnings"].append(f"The business's own profile does not list {name}.")

        # The delegation that lets the registry publish and serve this record.
        try:
            chain = verify_delegation_chain([record.get("delegation")], resolver=resolver, status=status, now=now_sec,
                                            roots=[did], required_scope=list(REGISTRY_SCOPES))
            if chain["delegate"] != registry_did:
                raise ValueError("it delegates to someone else")
            out["delegation"] = {"valid": True, "expiresAt": chain["expiresAt"]}
        except Exception as err:
            raise VerificationError(
                "delegation_invalid", f"the business has not delegated publication to this registry: {err}") from None

        # SPT's attestations.
        revocations = {r["jti"]: r for r in array(record.get("revocations"), "revocations")
                       if isinstance(prop(r, "jti"), str)}
        for compact in iterable(record.get("attestations"), "attestations"):
            if not _is_attestation_credential(compact):
                out["warnings"].append("The record carries a credential that is not an attestation; it was ignored.")
                continue
            out["facts"].append(_check_attestation(compact, did, registry_did, resolver, status, now_sec, revocations))
        valid = {f["kind"] for f in out["facts"] if f["status"] == "valid"}
        channels = next((f for f in out["facts"] if f["kind"] == "officialChannels" and f["status"] == "valid"), None)
        if channels:
            confirmed = channels["claims"].get("domains")
            if confirmed is None or not includes(confirmed, name):
                valid.discard("officialChannels")
                out["warnings"].append(f"{name} is not among the domains SPT confirmed.")
        if channels and asked_phone is not None:
            confirmed_phones = channels["claims"].get("phones")
            if confirmed_phones is None or not includes(confirmed_phones, asked_phone):
                valid.discard("officialChannels")
                out["warnings"].append(f"{asked_phone} is not among the phone numbers SPT confirmed.")
        for f in out["facts"]:
            if f["status"] == "unknown":
                out["warnings"].append(
                    f"The status of the {f['label'].lower()} credential could not be checked, so it is not counted.")
        out["level"] = level_for(valid)
        out["levelName"] = LEVEL_NAMES[out["level"]]
        legal = opt(opt(_valid_fact(out, "businessIdentity"), "claims"), "legalName")
        if isinstance(legal, str):
            out["business"]["legalName"] = legal
            if name_key(legal) != name_key(profile.get("name")):
                out["warnings"].append(
                    f'It calls itself "{template(profile, "name")}"; its verified legal name is "{legal}".')
        if not (is_num(record.get("level")) and record["level"] == out["level"]):
            out["warnings"].append(
                f"The registry lists Level {template(record, 'level')}; the credentials support Level {out['level']}.")

        # 4. What the agent sees versus the record.
        if truthy(observed):
            _compare(observed, profile, out)

        out["verified"] = out["level"] >= 1
        if not out["verified"]:
            out["failure"] = {"code": "not_verified", "message": "no current attestation supports Level 1"}
        # Nothing is asserted about a business that doesn't reach Level 1 here.
        scope = _verified_scope(record.get("scope"), valid if out["verified"] else set(), channels)
        if scope is not None:
            out["scope"] = scope
    except VerificationError as err:
        out["failure"] = {"code": err.code, "message": err.message}
        out["verified"] = False
        out["level"] = 0
        out["levelName"] = LEVEL_NAMES[0]
    out["observedMatches"] = len(out["mismatches"]) == 0
    out["summary"] = _summarize(out, registry_name)
    return out


def _is_scope(v: Any) -> bool:
    """A scope a record can carry: an object with a string explanation (older records have none)."""
    return isinstance(v, dict) and isinstance(v.get("explanation"), str)


def _verified_scope(scope: Any, valid: set, channels: dict | None) -> dict | None:
    """The record's scope, held to what verified: an assertion stays only while a valid
    attestation of its kind counts (phone control also needs a confirmed phone). The
    disclaimers stand as the registry signed them."""
    if not _is_scope(scope):
        return None

    def entries(value: Any) -> list[dict]:
        return [e for e in (value if isinstance(value, list) else [])
                if isinstance(e, dict) and isinstance(e.get("code"), str) and isinstance(e.get("statement"), str)]

    phones = opt(opt(channels, "claims"), "phones")
    has_phone = isinstance(phones, list) and len(phones) > 0
    asserts = [{"code": a["code"], "kind": a["kind"], "statement": a["statement"]}
               for a in entries(scope.get("asserts"))
               if isinstance(a.get("kind"), str) and a["kind"] in valid
               and (a["code"] != "phone-control" or has_phone)]
    does_not_assert = [{"code": d["code"], "statement": d["statement"]} for d in entries(scope.get("doesNotAssert"))]
    return {"asserts": asserts, "doesNotAssert": does_not_assert, "explanation": scope["explanation"]}


def _check_binding(domain: str, did: str, record_id: Any, registry_host: str, resolver: DidResolver,
                   dns: TxtResolver, warnings: list[str]) -> dict:
    def points_here(entry: Any) -> bool:
        try:
            u = URL(entry)
            return u.host == registry_host and includes(u.pathname.split("/"), record_id)
        except Exception:
            return False

    def binding(status: str, did_document: bool, dns_txt: bool, lower_assurance: bool) -> dict:
        return {"status": status, "didDocument": did_document, "dnsTxt": dns_txt, "lowerAssurance": lower_assurance}

    # DNS: _ffn.<domain> TXT naming this DID and this registry.
    dns_txt = False
    dns_mismatch = False
    try:
        txts = [t for t in map(parse_ffn_txt, array(dns.txt(ffn_txt_name(domain)), "TXT records")) if t is not None]
        dns_txt = any(t["did"] == did and t["registry"] == registry_host for t in txts)
        dns_mismatch = not dns_txt and len(txts) > 0
    except Exception:
        warnings.append(f"DNS for {domain} could not be checked.")
    if dns_mismatch:
        return binding("mismatch", False, False, False)

    # Key-only business: DNS is the whole binding, at lower assurance.
    if is_did_jwk(did):
        if not dns_txt:
            return binding("missing", False, False, True)
        warnings.append("This business uses a key-only identifier; its domain binding is DNS only (lower assurance).")
        return binding("dns-only", False, True, True)

    # did:web: the DID document on the queried domain is the binding.
    try:
        doc = resolver.resolve(f"did:web:{domain}")
    except Exception as err:
        # A missing document (404) is an answer; a network failure is not.
        missing = getattr(err, "missing", None)
        if missing is None:  # a resolver of the caller's own
            missing = re.search(r"HTTP 4[0-9][0-9]|does not match", str(err)) is not None
        return binding("missing" if missing else "unreachable", False, dns_txt, False)
    if not isinstance(doc, dict):
        return binding("missing", False, dns_txt, False)
    # A document whose alsoKnownAs or service isn't an array binds nothing.
    also_known_as = doc.get("alsoKnownAs", [])
    if not isinstance(also_known_as, list) or ("service" in doc and not isinstance(doc["service"], list)):
        return binding("missing", False, dns_txt, False)
    is_primary = did_web_host(did) == domain
    same_subject = doc.get("id") == did if is_primary else includes(also_known_as, did)
    entries = registry_entries_of(doc)
    if not same_subject or not entries:
        return binding("missing", False, dns_txt, False)
    if not any(points_here(e) for e in entries):
        return binding("mismatch", False, dns_txt, False)
    if not dns_txt:
        warnings.append(f"{domain} has no _ffn DNS record; the DID document alone binds it.")
    return binding("confirmed", True, dns_txt, False)


def _is_attestation_credential(compact: Any) -> bool:
    try:
        vct = prop(decode_jwt(compact.split("~")[0])[1], "vct")
        return kind_for_vct(js_str(vct)) in ATTESTATION_KINDS
    except Exception:
        return True  # undecodable: reported as an invalid fact


def _article(word: str) -> str:
    return "An" if re.match(r"[aeiou]", word, re.IGNORECASE) else "A"


def _check_attestation(compact: Any, did: str, registry_did: str, resolver: DidResolver, status: StatusChecker,
                       now: float, revocations: dict[str, dict]) -> dict:
    payload: Any = {}
    try:
        payload = decode_jwt(compact.split("~")[0])[1]
    except Exception:
        pass  # reported as invalid below
    any_kind = kind_for_vct(js_str(prop(payload, "vct")))
    is_attestation = any_kind in ATTESTATION_KINDS
    kind = any_kind if is_attestation else "businessIdentity"
    label = KIND_LABELS[kind]
    iss = prop(payload, "iss")
    base: dict[str, Any] = {"kind": kind, "label": label, "issuer": "" if iss is None else js_str(iss),
                            "claims": {}, "checks": []}
    if is_num(prop(payload, "iat")):
        base["issuedAt"] = iso(payload["iat"])
    if is_num(prop(payload, "exp")):
        base["expiresAt"] = iso(payload["exp"])

    def invalid(why: str) -> dict:
        sentence = f"{_article(label)} {label.lower()} credential is invalid: {why}."
        return {**base, "status": "invalid", "sentence": sentence}

    if not is_attestation:
        return invalid("not an attestation")
    try:
        v = verify_credential(compact, resolver=resolver, now=now)
    except CredentialError as err:
        if err.code == "expired":
            return {**base, "status": "expired",
                    "sentence": f"The {label.lower()} credential expired on {_day(base.get('expiresAt'))}."}
        return invalid(err.message)
    except Exception as err:
        return invalid(str(err))
    if v["iss"] != registry_did:
        return invalid("issued by someone other than the registry")
    if v["claims"].get("sub") != did:
        return invalid("issued about a different business")
    # Bound to a key the business still lists: a rotated-out key means a stale attestation.
    try:
        if is_did_jwk(did):
            bound = same_key(jwk_of_did_jwk(did), v["cnfJwk"])
        else:
            bound = resolver.controls_key(did, v["cnfJwk"])
    except Exception:
        bound = False
    if not bound:
        return invalid("bound to a key the business no longer lists")

    checks = nullish(opt(v["claims"].get("evidence"), "checks"), [])
    claims = {k: value for k, value in v["claims"].items() if k not in STRUCTURAL}
    fact = {**base, "claims": claims, "checks": checks}
    try:
        outcome = status.check(v["claims"].get("status"), registry_did)
    except Exception:
        outcome = {"status": "unknown"}
    revoked = revocations.get(template(v["claims"], "jti"))  # String(jti): a missing jti is "undefined"
    # The registry's signed record can withdraw a credential on its own; the
    # status list can too. Either one is enough.
    listed = ("suspended" if prop(revoked, "status") == "suspended" else "invalid") if revoked else None
    on_list = outcome["status"]
    effective = on_list if on_list in ("invalid", "suspended") else nullish(listed, on_list)
    if effective in ("invalid", "suspended"):
        st = "revoked" if effective == "invalid" else "suspended"
        result = {**fact, "status": st}
        why = ""
        if revoked:
            result["reason"] = revoked.get("reason")
            reason = revoked.get("reason")
            if not isinstance(reason, str):
                raise TypeError("reason.replace is not a function")
            why = f" ({reason.replace('-', ' ')})"
        result["sentence"] = f"The {label.lower()} credential was {st}{why}."
        return result
    sentence = _sentence_for(kind, claims, checks)
    if outcome["status"] == "unknown":
        sentence = f"{sentence[:-1]}, but its current status could not be checked."
    return {**fact, "status": outcome["status"], "sentence": sentence}


def _valid_fact(out: dict, kind: str) -> dict | None:
    return next((f for f in out["facts"] if f["kind"] == kind and f["status"] == "valid"), None)


def _compare(observed: dict, profile: dict, out: dict) -> None:
    if truthy(observed.get("name")):
        seen = name_key(observed["name"])
        legal = opt(out.get("business"), "legalName")
        # Only the legal name was verified; the profile name and DBAs are the business's own words.
        stated = [name_key(n) for n in [profile.get("name"), *iterable(nullish(profile.get("dba"), []), "dba")]]
        if truthy(legal) and name_key(legal) == seen:
            pass  # matches what SPT verified
        elif seen in stated:
            if truthy(legal):
                out["warnings"].append(f'"{js_str(observed["name"])}" matches only the name the business gives itself, '
                                       f"not its verified legal name ({legal}).")
        else:
            on_record = legal if legal is not None else template(profile, "name")
            out["mismatches"].append(f'The name "{js_str(observed["name"])}" does not match the record ({on_record}).')
    if truthy(observed.get("phone")):
        phone = None
        try:
            phone = normalize_phone(observed["phone"])
        except Exception:
            out["mismatches"].append(f'"{js_str(observed["phone"])}" is not a phone number the record could match.')
        official = opt(opt(_valid_fact(out, "officialChannels"), "claims"), "phones")
        if phone and not includes(nullish(official, nullish(profile.get("phones"), [])), phone):
            out["mismatches"].append(f"The phone {phone} is not one of the business's verified numbers.")
    if truthy(observed.get("address")) and truthy(profile.get("address")):
        seen = observed["address"].lower()
        a = profile["address"]
        parts = [x for x in (prop(a, "locality"), prop(a, "postalCode")) if truthy(x)]
        if not all(x.lower() in seen for x in parts):
            out["mismatches"].append(
                f'The address "{js_str(observed["address"])}" does not match the record '
                f"({template(a, 'locality')}, {template(a, 'region')}).")


def _summarize(out: dict, registry_name: Any) -> str:
    failure = out.get("failure")
    if failure and failure["code"] != "not_verified":
        return (f"{js_str(nullish(out.get('phone'), out['domain']))} could not be verified: {failure['message']}. "
                "Treat what the site says about itself as unverified.")
    b = out.get("business")
    if truthy(opt(b, "legalName")):
        same = name_key(b["legalName"]) == name_key(b.get("name"))
        name = b["legalName"] if same else f'{b["legalName"]} (calling itself "{template(b, "name")}")'
    else:
        name = js_str(nullish(opt(b, "name"), out["domain"]))
    subject = f"{out['phone']} ({out['domain']})" if truthy(out.get("phone")) else out["domain"]
    lines = [
        f"{subject} belongs to {name}, listed in the FFN Verified Business registry at Level {out['level']} "
        f"({out['levelName']})."
        if out["verified"]
        else f"{subject} belongs to {name}, but no current attestation supports a verification level."
    ]
    valid = [f for f in out["facts"] if f["status"] == "valid"]
    if valid:
        lines.append(f"{js_str(registry_name)} verified these facts: {' '.join(f['sentence'] for f in valid)}")
    lapsed = [f for f in out["facts"] if f["status"] != "valid"]
    if lapsed:
        lines.append(" ".join(f["sentence"] for f in lapsed))
    kinds = {f["kind"] for f in out["facts"]}
    missing = [k for k in ATTESTATION_KINDS if k not in kinds]
    if missing:
        lines.append(f"Not checked: {', '.join(KIND_LABELS[k].lower() for k in missing)}.")
    if out["mismatches"]:
        lines.append(f"Mismatches: {' '.join(out['mismatches'])}")
    phones = opt(opt(next((f for f in valid if f["kind"] == "officialChannels"), None), "claims"), "phones")
    if isinstance(phones, list) and len(phones) > 0:
        lines.append("A verified phone number shows the business controls it when you call it, not that a call or "
                     "text you receive comes from the business.")
    lines.append("These are verified facts with dates, not a rating or a recommendation.")
    return " ".join(lines)
