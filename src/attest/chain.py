"""Remote-attestation quote-chain verification and key registration.

A quote link is a mapping with these fields:

    key_id          lowercase SHA-256 hex digest of public_key
    public_key      bytes
    nonce           bytes
    pcr_digest      bytes
    owner           non-empty string
    issued_at       integer Unix time, inclusive
    expires_at      integer Unix time, inclusive
    parent          parent link mapping, or None for the root
    parent_key_id   parent key_id, or None for the root
    signature       HMAC-SHA256 bytes

Signatures use the parent public key (the root is self-signed) over
quote_payload(nonce, key_id, pcr_digest).  A complete proof is the leaf link
with its parents nested through parent.  A flattened chain is ordered from the
root to the leaf.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Sequence

_PAYLOAD_DOMAIN = b"attest-link-v1"


def _is_bytes(value: Any) -> bool:
    return isinstance(value, (bytes, bytearray, memoryview))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pack(field: bytes, value: bytes) -> bytes:
    """Length-prefix one field so concatenations stay unambiguous."""
    return field + len(value).to_bytes(8, "big") + value


def quote_payload(nonce: bytes, key_id: str, pcr_digest: bytes) -> bytes:
    """Return the canonical bytes covered by a link signature.

    key_id is the lowercase SHA-256 hex digest of the link public key, so a
    payload that omits it lets a signature be replayed with another key.  The
    encoding must be unambiguous and must cover nonce, key_id and pcr_digest.
    """
    if not isinstance(key_id, str):
        raise TypeError("key_id must be a string")
    if not _is_bytes(nonce):
        raise TypeError("nonce must be bytes")
    if not _is_bytes(pcr_digest):
        raise TypeError("pcr_digest must be bytes")
    # Domain separation plus length prefixes: changing any field, including
    # swapping bytes between fields, changes the payload.
    return (
        _PAYLOAD_DOMAIN
        + _pack(b"nonce", bytes(nonce))
        + _pack(b"key_id", key_id.encode("utf-8"))
        + _pack(b"pcr_digest", bytes(pcr_digest))
    )


def verify_link(link: dict[str, Any], parent_key: bytes) -> bool:
    """Verify one link signature with parent_key.

    The signature is HMAC-SHA256(parent_key, quote_payload(...)).  The link
    public key must hash to link key_id.  Malformed links return False.  The
    final comparison must use hmac.compare_digest rather than ordinary
    equality, and non-byte signatures must be rejected before comparison.
    """
    if not isinstance(link, dict):
        return False
    if not _is_bytes(parent_key):
        return False
    try:
        public_key = link["public_key"]
        key_id = link["key_id"]
        nonce = link["nonce"]
        pcr_digest = link["pcr_digest"]
        signature = link["signature"]
    except (KeyError, TypeError):
        return False

    if not _is_bytes(public_key):
        return False
    if not isinstance(key_id, str) or not _is_bytes(nonce) or not _is_bytes(
        pcr_digest
    ):
        return False
    # The link key must actually hash to the id it claims; otherwise a
    # signature could be presented under an unrelated key id.
    if hashlib.sha256(bytes(public_key)).hexdigest() != key_id:
        return False
    # Reject non-byte signatures (including objects with permissive __eq__)
    # before any comparison happens.
    if not _is_bytes(signature):
        return False

    try:
        expected = hmac.new(
            bytes(parent_key),
            quote_payload(bytes(nonce), key_id, bytes(pcr_digest)),
            hashlib.sha256,
        ).digest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, bytes(signature))


def chain_depth(quotes: Sequence[dict[str, Any]]) -> int:
    """Validate root-to-leaf linkage and return the chain depth.

    The first link is the root: its parent_key_id is None.  Every later link
    must name the previous link as its parent_key_id, and every public key must
    hash to its key_id.  Missing parents, duplicate ids and out-of-order links
    raise ValueError.  This function checks topology, not signatures.
    """
    if isinstance(quotes, (str, bytes, bytearray)) or not isinstance(
        quotes, Sequence
    ):
        raise ValueError("chain must be a sequence of links")
    links = list(quotes)
    if not links:
        raise ValueError("empty chain")

    seen: set[str] = set()
    previous_key_id: str | None = None
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            raise ValueError(f"link {index} is not a mapping")
        key_id = link.get("key_id")
        public_key = link.get("public_key")
        if not isinstance(key_id, str) or not _is_bytes(public_key):
            raise ValueError(f"link {index} has malformed identity fields")
        if hashlib.sha256(bytes(public_key)).hexdigest() != key_id:
            raise ValueError(f"link {index} key_id does not match public_key")
        if key_id in seen:
            raise ValueError(f"duplicate key_id {key_id!r}")
        seen.add(key_id)

        parent_key_id = link.get("parent_key_id")
        if index == 0:
            if parent_key_id is not None:
                raise ValueError("root link must not name a parent")
        elif parent_key_id != previous_key_id:
            # Missing, out-of-order, or unrelated parent.
            raise ValueError(
                f"link {index} does not link to the preceding link"
            )
        previous_key_id = key_id

    return len(links)


def binding_ok(quote: dict[str, Any], nonce: bytes, public_key: bytes) -> bool:
    """Check that quote is bound to the complete nonce and public key.

    The nonce comparison is exact, never a prefix match.  The public key must
    equal quote public_key and its SHA-256 digest must equal quote key_id.
    """
    if not isinstance(quote, dict):
        return False
    if not _is_bytes(nonce) or not _is_bytes(public_key):
        return False

    quote_nonce = quote.get("nonce")
    quote_public_key = quote.get("public_key")
    quote_key_id = quote.get("key_id")
    if not _is_bytes(quote_nonce) or not _is_bytes(quote_public_key):
        return False
    if not isinstance(quote_key_id, str):
        return False

    # Constant-time exact comparison; lengths are part of the comparison, so a
    # prefix of the nonce never matches.
    if not hmac.compare_digest(bytes(quote_nonce), bytes(nonce)):
        return False
    if not hmac.compare_digest(bytes(quote_public_key), bytes(public_key)):
        return False
    digest = hashlib.sha256(bytes(public_key)).hexdigest()
    try:
        matches = hmac.compare_digest(
            digest.encode("utf-8"), quote_key_id.encode("utf-8")
        )
    except UnicodeError:
        return False
    return matches


def freshness_ok(quote: dict[str, Any], now: int, window: int) -> bool:
    """Check inclusive validity and a finite maximum lifetime.

    Accept exactly when issued_at <= now <= expires_at and
    0 < expires_at - issued_at <= window.  A non-integer, non-positive or
    infinite window is invalid.  Both validity endpoints are inclusive.
    """
    if not isinstance(quote, dict):
        return False
    if not _is_int(window) or window <= 0:
        return False
    if not _is_int(now):
        return False

    issued_at = quote.get("issued_at")
    expires_at = quote.get("expires_at")
    if not _is_int(issued_at) or not _is_int(expires_at):
        return False

    # Both endpoints inclusive: not-yet-valid and already-expired are rejected.
    if not (issued_at <= now <= expires_at):
        return False
    lifetime = expires_at - issued_at
    if not (0 < lifetime <= window):
        return False
    return True


def _flatten_chain(leaf: Any) -> list[dict[str, Any]]:
    """Flatten nested parent links, ordered root to leaf.

    A missing parent where one is named, a cycle, or a malformed node is a
    ValueError rather than a silently short chain.
    """
    links: list[dict[str, Any]] = []
    seen: set[str] = set()
    node = leaf
    while node is not None:
        if not isinstance(node, dict):
            raise ValueError("malformed parent link")
        key_id = node.get("key_id")
        if not isinstance(key_id, str):
            raise ValueError("link is missing key_id")
        if key_id in seen:
            raise ValueError("cycle in parent links")
        seen.add(key_id)
        links.append(node)
        node = node.get("parent")
    links.reverse()
    return links


def _verify_nested_chain(leaf: Any) -> tuple[list[dict[str, Any]], int]:
    """Verify topology and every signature of a nested proof.

    Returns the flattened root-to-leaf links and the depth.  Every level is
    verified, not only the leaf, so tampering with any ancestor is caught.
    """
    links = _flatten_chain(leaf)
    depth = chain_depth(links)
    for index, link in enumerate(links):
        signing_key = link["public_key"] if index == 0 else links[index - 1][
            "public_key"
        ]
        if not verify_link(link, signing_key):
            raise ValueError(f"invalid signature at chain level {index}")
    return links, depth


def register(
    store: dict[str, Any],
    key_id: str,
    quote: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """Register a verified quote and return its stable store record.

    Registration verifies the complete nested chain, all signatures, the leaf
    key binding, and now within the quote validity interval.  The record is:

        key_id, public_key, owner, quote, registered_at, chain, revoked

    chain is the flattened root-to-leaf key_id list.  The first nonce use is
    recorded in store["__nonces__"] and a later different key presenting the
    same nonce is rejected with ValueError.  Re-registering the same key and
    owner returns the original record unchanged.  An existing registration
    with a different owner or public key raises PermissionError.

    Invalid proofs, stale quotes and replayed nonces raise ValueError.
    """
    if not isinstance(store, dict):
        raise ValueError("store must be a mapping")
    if not isinstance(quote, dict):
        raise ValueError("quote must be a mapping")
    if not isinstance(key_id, str) or not _is_int(now):
        raise ValueError("malformed registration arguments")

    links, _depth = _verify_nested_chain(quote)
    leaf = links[-1]

    if leaf["key_id"] != key_id:
        raise ValueError("key_id does not match the proof leaf")

    public_key = leaf["public_key"]
    if not _is_bytes(public_key):
        raise ValueError("leaf public_key is malformed")
    public_key = bytes(public_key)

    # The leaf must be self-consistent: complete nonce plus key digest.
    if not binding_ok(leaf, leaf["nonce"], public_key):
        raise ValueError("leaf is not bound to its nonce and key")

    owner = leaf.get("owner")
    if not isinstance(owner, str) or not owner:
        raise ValueError("owner must be a non-empty string")

    issued_at = leaf.get("issued_at")
    expires_at = leaf.get("expires_at")
    if not _is_int(issued_at) or not _is_int(expires_at):
        raise ValueError("quote validity times must be integers")
    # Both endpoints inclusive; a not-yet-valid proof is rejected.
    if not (issued_at <= now <= expires_at):
        raise ValueError("quote is not valid at the current time")

    # Never overwrite somebody else's registration for this key.
    existing = store.get(key_id)
    if isinstance(existing, dict):
        if existing.get("owner") != owner or existing.get("public_key") != public_key:
            raise PermissionError("key is already registered by another owner")
        # Re-registering the same key and owner is stable and side-effect free.
        return existing

    nonces = store.setdefault("__nonces__", {})
    if not isinstance(nonces, dict):
        raise ValueError("nonce ledger is malformed")
    nonce = bytes(leaf["nonce"])
    previous_owner_key = nonces.get(nonce)
    if previous_owner_key is not None and previous_owner_key != key_id:
        raise ValueError("nonce has already been used by another key")

    record = {
        "key_id": key_id,
        "public_key": public_key,
        "owner": owner,
        "quote": quote,
        "registered_at": now,
        "chain": [link["key_id"] for link in links],
        "revoked": False,
    }
    store[key_id] = record
    nonces[nonce] = key_id
    return record


def revoke(store: dict[str, Any], key_id: str, now: int) -> int:
    """Revoke key_id and every registration whose chain references it.

    Removal is recursive: records that named the revoked key are removed, then
    records that named any removed key are removed, and so on.  The nonce
    ledger is retained.  Return the number of records removed, or 0 when
    key_id was not registered.
    """
    if not isinstance(store, dict):
        return 0
    if key_id not in store or key_id == "__nonces__":
        return 0
    if not isinstance(store.get(key_id), dict):
        return 0

    removed: set[str] = set()
    pending = [key_id]
    while pending:
        target = pending.pop()
        if target in removed or target == "__nonces__":
            continue
        record = store.get(target)
        if not isinstance(record, dict):
            continue
        # Remove the record itself and then everything whose chain relied on
        # it; the chain list is stored root to leaf and contains the record's
        # own key_id as its last entry.
        del store[target]
        removed.add(target)
        for other_id, other in list(store.items()):
            if other_id == "__nonces__" or other_id in removed:
                continue
            if not isinstance(other, dict):
                continue
            chain = other.get("chain")
            if isinstance(chain, (list, tuple)) and target in chain:
                pending.append(other_id)

    # Nonce ledger is intentionally retained after revocation.
    return len(removed)


def _validate_request(
    request: dict[str, Any],
    policy: dict[str, Any],
    now: int,
) -> None:
    """Validate one attestation request in a fresh, isolated context."""
    if not isinstance(request, dict):
        raise TypeError("request must be a mapping")
    quote = request.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("request quote must be a mapping")

    # Local per-request state only; no parent key is carried between requests.
    links, depth = _verify_nested_chain(quote)
    leaf = links[-1]

    key_id = request.get("key_id")
    if not isinstance(key_id, str) or leaf["key_id"] != key_id:
        raise ValueError("request key_id does not match its proof")

    public_key = request.get("public_key")
    if not _is_bytes(public_key):
        raise ValueError("request public_key is malformed")
    if not binding_ok(leaf, request.get("nonce"), public_key):
        raise ValueError("proof is not bound to the request nonce and key")

    if not isinstance(policy, dict):
        raise ValueError("policy must be a mapping")

    min_depth = policy.get("min_depth", 0)
    if not _is_int(min_depth) or min_depth < 0:
        raise ValueError("policy min_depth is invalid")
    if depth < min_depth:
        raise ValueError("proof chain is too shallow")

    if not freshness_ok(leaf, now, policy.get("window")):
        raise ValueError("proof is stale or has an invalid lifetime")


def attest_batch(
    requests: Sequence[dict[str, Any]],
    policy: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """Validate independent attestation requests under policy.

    Each request supplies key_id, quote, nonce and public_key.  policy supplies
    window and min_depth.  A request is accepted only when its full chain
    verifies, its depth is at least min_depth, binding_ok succeeds and
    freshness_ok succeeds.  Failure of one request never aborts or changes the
    context of another.  Return:

        {
            "results": [
                {"key_id": ..., "accepted": bool, "reason": None or str},
                ...
            ],
            "accepted": int,
            "rejected": int,
        }

    reason is the exception class name for a rejected request and None for an
    accepted request.
    """
    results: list[dict[str, Any]] = []
    accepted = 0
    rejected = 0

    for request in requests:
        request_key_id = (
            request.get("key_id") if isinstance(request, dict) else None
        )
        try:
            _validate_request(request, policy, now)
        except Exception as exc:  # one bad request must not abort the batch
            results.append(
                {
                    "key_id": request_key_id,
                    "accepted": False,
                    "reason": type(exc).__name__,
                }
            )
            rejected += 1
        else:
            results.append(
                {"key_id": request_key_id, "accepted": True, "reason": None}
            )
            accepted += 1

    return {"results": results, "accepted": accepted, "rejected": rejected}
