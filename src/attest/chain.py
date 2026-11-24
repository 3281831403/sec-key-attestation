"""Remote-attestation quote-chain verification and key registration.

The module deliberately contains only eight public stubs.  A quote link is a
mapping with these fields:

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

from typing import Any, Sequence


def quote_payload(nonce: bytes, key_id: str, pcr_digest: bytes) -> bytes:
    """Return the canonical bytes covered by a link signature.

    key_id is the lowercase SHA-256 hex digest of the link public key, so a
    payload that omits it lets a signature be replayed with another key.  The
    encoding must be unambiguous and must cover nonce, key_id and pcr_digest.
    """
    raise NotImplementedError


def verify_link(link: dict[str, Any], parent_key: bytes) -> bool:
    """Verify one link signature with parent_key.

    The signature is HMAC-SHA256(parent_key, quote_payload(...)).  The link
    public key must hash to link key_id.  Malformed links return False.  The
    final comparison must use hmac.compare_digest rather than ordinary
    equality, and non-byte signatures must be rejected before comparison.
    """
    raise NotImplementedError


def chain_depth(quotes: Sequence[dict[str, Any]]) -> int:
    """Validate root-to-leaf linkage and return the chain depth.

    The first link is the root: its parent_key_id is None.  Every later link
    must name the previous link as its parent_key_id, and every public key must
    hash to its key_id.  Missing parents, duplicate ids and out-of-order links
    raise ValueError.  This function checks topology, not signatures.
    """
    raise NotImplementedError


def binding_ok(quote: dict[str, Any], nonce: bytes, public_key: bytes) -> bool:
    """Check that quote is bound to the complete nonce and public key.

    The nonce comparison is exact, never a prefix match.  The public key must
    equal quote public_key and its SHA-256 digest must equal quote key_id.
    """
    raise NotImplementedError


def freshness_ok(quote: dict[str, Any], now: int, window: int) -> bool:
    """Check inclusive validity and a finite maximum lifetime.

    Accept exactly when issued_at <= now <= expires_at and
    0 < expires_at - issued_at <= window.  A non-integer, non-positive or
    infinite window is invalid.  Both validity endpoints are inclusive.
    """
    raise NotImplementedError


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
    raise NotImplementedError


def revoke(store: dict[str, Any], key_id: str, now: int) -> int:
    """Revoke key_id and every registration whose chain references it.

    Removal is recursive: records that named the revoked key are removed, then
    records that named any removed key are removed, and so on.  The nonce
    ledger is retained.  Return the number of records removed, or 0 when
    key_id was not registered.
    """
    raise NotImplementedError


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
    raise NotImplementedError