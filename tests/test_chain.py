"""Adversarial tests for the attestation chain challenge."""

from __future__ import annotations

import hashlib
import hmac
import inspect

import pytest

import attest.chain as chain_module
from attest.chain import (
    attest_batch,
    binding_ok,
    chain_depth,
    freshness_ok,
    quote_payload,
    register,
    revoke,
    verify_link,
)

ISSUED = 100
EXPIRES = 160
WINDOW = 60
NOW = 120


def _public_key(tag: str) -> bytes:
    return hashlib.sha256(("public-key:" + tag).encode("utf-8")).digest()


def _key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def _make_link(
    *,
    nonce: bytes,
    public_key: bytes,
    pcr_digest: bytes,
    parent: dict | None = None,
    owner: str = "alice",
    issued_at: int = ISSUED,
    expires_at: int = EXPIRES,
) -> dict:
    link = {
        "key_id": _key_id(public_key),
        "public_key": public_key,
        "nonce": nonce,
        "pcr_digest": pcr_digest,
        "owner": owner,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "parent": parent,
        "parent_key_id": None if parent is None else parent["key_id"],
    }
    signing_key = public_key if parent is None else parent["public_key"]
    link["signature"] = hmac.new(
        signing_key,
        quote_payload(nonce, link["key_id"], pcr_digest),
        hashlib.sha256,
    ).digest()
    return link


def _make_chain(
    prefix: str,
    *,
    depth: int = 3,
    leaf_nonce: bytes | None = None,
    owner: str = "alice",
    issued_at: int = ISSUED,
    expires_at: int = EXPIRES,
) -> tuple[dict, list[dict]]:
    links: list[dict] = []
    parent: dict | None = None
    for index in range(depth):
        is_leaf = index == depth - 1
        nonce = (
            leaf_nonce
            if is_leaf and leaf_nonce is not None
            else f"{prefix}:nonce:{index}".encode("utf-8")
        )
        parent = _make_link(
            nonce=nonce,
            public_key=_public_key(f"{prefix}:{index}"),
            pcr_digest=f"{prefix}:pcr:{index}".encode("utf-8"),
            parent=parent,
            owner=owner,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        links.append(parent)
    return links[-1], links


def _request(leaf: dict) -> dict:
    return {
        "key_id": leaf["key_id"],
        "quote": leaf,
        "nonce": leaf["nonce"],
        "public_key": leaf["public_key"],
    }


def _accepted_flags(result: dict) -> list[bool]:
    return [entry["accepted"] for entry in result["results"]]


class _AlwaysEqual:
    def __eq__(self, other: object) -> bool:
        return True


def test_payload_binds_nonce_and_public_key_digest() -> None:
    key_a = _key_id(_public_key("payload-a"))
    key_b = _key_id(_public_key("payload-b"))
    baseline = quote_payload(b"nonce-a", key_a, b"pcr")
    assert isinstance(baseline, bytes)
    assert baseline != quote_payload(b"nonce-b", key_a, b"pcr")
    assert baseline != quote_payload(b"nonce-a", key_b, b"pcr")
    assert baseline != quote_payload(b"nonce-a", key_a, b"other-pcr")


def test_verify_link_uses_constant_time_comparison() -> None:
    root = _make_link(
        nonce=b"root-nonce",
        public_key=_public_key("ct-root"),
        pcr_digest=b"root-pcr",
    )
    child = _make_link(
        nonce=b"child-nonce",
        public_key=_public_key("ct-child"),
        pcr_digest=b"child-pcr",
        parent=root,
    )
    assert verify_link(child, root["public_key"]) is True
    assert verify_link(child, _public_key("wrong-parent")) is False

    forged = dict(child)
    forged["signature"] = _AlwaysEqual()
    assert verify_link(forged, root["public_key"]) is False

    source = inspect.getsource(chain_module.verify_link)
    assert "compare_digest" in source


def test_chain_verification_checks_all_parent_signatures() -> None:
    leaf, links = _make_chain("all-levels")
    links[0]["pcr_digest"] = b"forged-root"
    assert verify_link(leaf, links[-2]["public_key"]) is True
    with pytest.raises(ValueError):
        register({}, leaf["key_id"], leaf, NOW)


def test_chain_depth_rejects_missing_parent() -> None:
    _, links = _make_chain("depth")
    assert chain_depth(links) == 3
    with pytest.raises(ValueError):
        chain_depth(links[1:])
    with pytest.raises(ValueError):
        chain_depth(list(reversed(links)))


def test_binding_requires_full_nonce_and_public_key() -> None:
    leaf, _ = _make_chain("binding", leaf_nonce=b"abcdef")
    assert binding_ok(leaf, b"abcdef", leaf["public_key"]) is True
    assert binding_ok(leaf, b"abc", leaf["public_key"]) is False
    assert binding_ok(leaf, b"abcdef", _public_key("other")) is False


def test_freshness_rejects_not_yet_valid_and_overlong() -> None:
    leaf, _ = _make_chain("fresh", issued_at=100, expires_at=160)
    assert freshness_ok(leaf, 100, 60) is True
    assert freshness_ok(leaf, 160, 60) is True
    assert freshness_ok(leaf, 99, 60) is False
    assert freshness_ok(leaf, 161, 60) is False
    assert freshness_ok(leaf, 130, 59) is False
    assert freshness_ok(leaf, 130, float("inf")) is False


def test_valid_chain_registers_successfully() -> None:
    leaf, links = _make_chain("register-ok")
    store: dict = {}
    record = register(store, leaf["key_id"], leaf, NOW)
    assert record["key_id"] == leaf["key_id"]
    assert record["public_key"] == leaf["public_key"]
    assert record["owner"] == "alice"
    assert record["registered_at"] == NOW
    assert record["revoked"] is False
    assert record["chain"] == [link["key_id"] for link in links]
    assert store[leaf["key_id"]]["quote"]["nonce"] == leaf["nonce"]


def test_register_rejects_takeover_by_other_owner() -> None:
    leaf, _ = _make_chain("owner", owner="alice")
    store: dict = {}
    register(store, leaf["key_id"], leaf, NOW)

    takeover, _ = _make_chain(
        "owner",
        leaf_nonce=b"takeover-nonce",
        owner="mallory",
    )
    assert takeover["key_id"] == leaf["key_id"]
    with pytest.raises(PermissionError):
        register(store, leaf["key_id"], takeover, NOW)
    assert store[leaf["key_id"]]["owner"] == "alice"


def test_register_is_idempotent() -> None:
    leaf, _ = _make_chain("idempotent")
    store: dict = {}
    first = register(store, leaf["key_id"], leaf, NOW)
    second = register(store, leaf["key_id"], leaf, NOW + 10)
    assert second == first
    assert second["registered_at"] == NOW
    records = [value for key, value in store.items() if key != "__nonces__"]
    assert len(records) == 1


def test_revoke_removes_chain_references() -> None:
    leaf, links = _make_chain("revoke")
    root, middle, _ = links
    store: dict = {}
    register(store, root["key_id"], root, NOW)
    register(store, middle["key_id"], middle, NOW)
    register(store, leaf["key_id"], leaf, NOW)

    removed = revoke(store, middle["key_id"], NOW + 10)
    assert removed == 2
    assert middle["key_id"] not in store
    assert leaf["key_id"] not in store
    assert root["key_id"] in store
    for key, value in store.items():
        if key == "__nonces__":
            continue
        assert middle["key_id"] not in value["chain"]
    assert revoke(store, middle["key_id"], NOW + 11) == 0


def test_attest_batch_does_not_reuse_parent_context() -> None:
    first, _ = _make_chain("batch-first")
    second, _ = _make_chain("batch-second")
    policy = {"window": WINDOW, "min_depth": 3}
    requests = [_request(first), _request(second)]

    result = attest_batch(requests, policy, NOW)
    assert _accepted_flags(result) == [True, True]
    assert result["accepted"] == 2
    assert result["rejected"] == 0

    reverse = attest_batch(list(reversed(requests)), policy, NOW)
    assert _accepted_flags(reverse) == [True, True]


def test_tampered_middle_link_fails_chain_verification() -> None:
    leaf, links = _make_chain("tamper-middle")
    middle = links[1]
    middle["pcr_digest"] = b"tampered"
    assert verify_link(leaf, middle["public_key"]) is True
    with pytest.raises(ValueError):
        register({}, leaf["key_id"], leaf, NOW)


def test_replay_of_used_nonce_is_rejected() -> None:
    first, _ = _make_chain("replay-first", leaf_nonce=b"shared-nonce")
    second, _ = _make_chain("replay-second", leaf_nonce=b"shared-nonce")
    store: dict = {}
    register(store, first["key_id"], first, NOW)
    with pytest.raises(ValueError):
        register(store, second["key_id"], second, NOW)
    assert second["key_id"] not in store


def test_same_key_registration_is_stable() -> None:
    leaf, _ = _make_chain("stable", leaf_nonce=b"first-nonce")
    store: dict = {}
    first = register(store, leaf["key_id"], leaf, NOW)

    other, _ = _make_chain("stable", leaf_nonce=b"second-nonce")
    assert other["key_id"] == leaf["key_id"]
    second = register(store, other["key_id"], other, NOW + 10)
    assert second == first
    assert second["registered_at"] == NOW
    assert store[leaf["key_id"]]["quote"]["nonce"] == b"first-nonce"


def test_batch_results_match_individual_validation() -> None:
    valid, _ = _make_chain("individual-valid")
    invalid, invalid_links = _make_chain("individual-invalid")
    invalid_links[1]["pcr_digest"] = b"bad-middle"
    policy = {"window": WINDOW, "min_depth": 3}
    requests = [_request(valid), _request(invalid)]

    combined = attest_batch(requests, policy, NOW)
    solo_valid = attest_batch([requests[0]], policy, NOW)
    solo_invalid = attest_batch([requests[1]], policy, NOW)

    assert _accepted_flags(combined) == [True, False]
    assert combined["accepted"] == 1
    assert combined["rejected"] == 1
    assert _accepted_flags(combined) == _accepted_flags(solo_valid) + _accepted_flags(
        solo_invalid
    )
    assert combined["accepted"] == solo_valid["accepted"] + solo_invalid["accepted"]
    assert combined["rejected"] == solo_valid["rejected"] + solo_invalid["rejected"]