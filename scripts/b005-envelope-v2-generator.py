#!/usr/bin/env python3
"""Regenerate and independently sanity-check the committed B005 v2 vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts/b005-envelope-v2-fixtures.json"
TARGET = ROOT / "test-vectors/b005-envelope-v2.txt"
SECP_VECTOR = ROOT / "test-vectors/secp256k1-ecdsa-v1.txt"


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)
ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
       (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
RC = (1, 0x8082, 0x800000000000808A, 0x8000000080008000,
      0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
      0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B,
      0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
      0x8000000000000080, 0x800A, 0x800000008000000A, 0x8000000080008081,
      0x8000000000008080, 0x80000001, 0x8000000080008008)
MASK = (1 << 64) - 1


def rotl(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (64 - amount))) & MASK if amount else value


def keccak_f(a: list[int]) -> None:
    for rc in RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\0" * ((rate - len(padded) % rate - 1) % rate))
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        keccak_f(state)
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % P == 0:
        return None
    if left == right:
        slope = (3 * left[0] * left[0]) * pow(2 * left[1], P - 2, P) % P
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], P - 2, P) % P
    x = (slope * slope - left[0] - right[0]) % P
    return x, (slope * (left[0] - x) - left[1]) % P


def point_mul(scalar, point=G):
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def decompress_public_key(encoded: bytes):
    assert len(encoded) == 33 and encoded[0] in (2, 3)
    x = int.from_bytes(encoded[1:], "big")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (encoded[0] & 1):
        y = P - y
    assert (y * y - x * x * x - 7) % P == 0
    return x, y


def compress_public_key(point) -> bytes:
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def recover_public_key(digest: bytes, signature: bytes) -> bytes:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    recovery_id = signature[64]
    assert 1 <= r < N and 1 <= s <= N // 2 and recovery_id in (0, 1)
    r_point = decompress_public_key(bytes([2 | recovery_id]) + r.to_bytes(32, "big"))
    recovered = point_mul(pow(r, N - 2, N), point_add(point_mul(s, r_point), point_mul((-int.from_bytes(digest, "big")) % N)))
    return compress_public_key(recovered)


def parse_vectors(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def build_envelope(common: dict, item: dict, certificate: bytes = b"") -> bytes:
    name = item["display_name"].encode()
    body = (
        b"\x01" + bytes.fromhex(common["registrar"] + common["anchor_operator"] + common["nonce"])
        + b"\x01" + bytes.fromhex(common["authority_public_key"])
        + b"\x00" + int(item["enin_seconds"]).to_bytes(2, "big")
        + int(item["valid_from_enin"]).to_bytes(4, "big")
        + int(item["valid_through_enin"]).to_bytes(4, "big")
        + int(item["relay_expires_at_enin"]).to_bytes(4, "big")
        + b"\x02" + bytes.fromhex(common["event_code_hash"])
        + bytes([len(name)]) + name + bytes([len(certificate)]) + certificate
    )
    return body + bytes.fromhex(item["signature"])


def validate_ecdsa_profile() -> None:
    values = parse_vectors(SECP_VECTOR)
    digest = bytes.fromhex(values["message_hash"])
    public_key = bytes.fromhex(values["public_key_compressed"])
    r = int(values["expected_r"], 16)
    s = int(values["expected_s"], 16)
    recovery_id = int(values["expected_v"])
    w = pow(s, N - 2, N)
    point = point_add(point_mul(r * w % N, decompress_public_key(public_key)), point_mul(int.from_bytes(digest, "big") * w % N))
    assert point is not None and point[0] % N == r
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recovery_id])
    assert recover_public_key(digest, signature) == public_key


def validate_delegation_certificate(common: dict, certificate: bytes) -> None:
    assert certificate[:2] == bytes.fromhex("d284") and len(certificate) == 222
    protected = certificate[4:65]
    payload = certificate[68:156]
    signature = certificate[157:]
    assert certificate[65:68] == bytes.fromhex("a05858")
    assert len(signature) == 65 and signature[0] == 0x40
    signature = signature[1:]
    expected_protected = (
        bytes.fromhex("a301382e03782c")
        + b"application/vnd.levarac.delegation-cert+cbor"
        + bytes.fromhex("0448f5df3c6eefaf5217")
    )
    assert protected == expected_protected
    assert payload[:3] == bytes.fromhex("a60101")
    assert payload[1:38].hex() == "0101025820" + common["event_id"]
    assert payload[38:74].hex() == "035821" + common["delegate_public_key"]
    assert payload[74:77] == bytes.fromhex("040105")
    assert payload[77:88] == bytes.fromhex("1a005b8d76061a005b8d8a")
    sig_structure = b"\x84\x6aSignature1\x58" + bytes([len(protected)]) + protected + b"\x40\x58\x58" + payload
    digest = hashlib.sha256(sig_structure).digest()
    assert any(
        recover_public_key(digest, signature + bytes([recovery_id])) == bytes.fromhex(common["authority_public_key"])
        for recovery_id in (0, 1)
    )


def validate(common: dict, v1: bytes, v2: bytes) -> None:
    assert keccak256(b"") == bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    key_set = bytes.fromhex("a3010102815821" + common["authority_public_key"] + "0301")
    assert hashlib.sha256(b"levarac:event-key-set-digest:v1\0" + key_set).hexdigest() == common["event_key_set_digest"]
    preimage = keccak256(b"levarac:event:v1") + bytes.fromhex("00" * 12 + common["registrar"] + "00" * 12 + common["anchor_operator"] + common["nonce"] + common["event_key_set_digest"])
    assert keccak256(preimage).hex() == common["event_id"]
    for envelope, expected_key, current, hop in ((v1, common["authority_public_key"], 6000000, 0), (v2, common["delegate_public_key"], 6000000, 1)):
        assert len(envelope) <= 508 and envelope[:1] == b"\x01"
        container = bytes([3, hop]) + len(envelope).to_bytes(2, "big") + envelope
        assert len(container) <= 512 and container[0] == 3 and container[1] == hop
        assert int.from_bytes(container[2:4], "big") == len(envelope)
        digest = hashlib.sha256(b"barnard-b005-event-info:v1" + envelope[:-65]).digest()
        assert recover_public_key(digest, envelope[-65:]).hex() == expected_key
        valid_from = int.from_bytes(envelope[110:114], "big")
        valid_through = int.from_bytes(envelope[114:118], "big")
        relay_expires = int.from_bytes(envelope[118:122], "big")
        assert valid_from <= current < relay_expires <= valid_through
        assert relay_expires - valid_from <= 12
        assert hashlib.sha256(common["event_id"].encode()).hexdigest()[:16] == common["event_code_hash"]
        name_length = envelope[131]
        certificate_length = envelope[132 + name_length]
        assert 1 <= name_length <= 64
        assert 0 <= certificate_length <= 255
        assert 133 + name_length + certificate_length + 65 == len(envelope)
        if certificate_length:
            certificate = envelope[133 + name_length:133 + name_length + certificate_length]
            assert certificate_length == 222
            assert bytes.fromhex(common["delegate_public_key"]) in certificate
            validate_delegation_certificate(common, certificate)
    assert v1[0] == 1 and v2[0] == 1
    assert len(v1) == 256 and len(v2) == 438
    assert bytes.fromhex(common["negative_census_v2_prefix"])[:1] != b"\x03"
    validate_ecdsa_profile()


def render(data: dict) -> str:
    common = data
    key_set = "a3010102815821" + common["authority_public_key"] + "0301"
    digest = hashlib.sha256(b"levarac:event-key-set-digest:v1\0" + bytes.fromhex(key_set)).hexdigest()
    v1 = build_envelope(common, {**data["v1"], "signature": data["v1"]["signature"]})
    v2 = build_envelope(common, {**data["v1"], **data["v2"], "signature": data["v2"]["signature"]}, bytes.fromhex(data["v2"]["delegation_cert"]))
    validate({**common, "event_key_set_digest": digest, "delegate_public_key": data["v2"]["delegate_public_key"]}, v1, v2)
    c1 = b"\x03\x00" + len(v1).to_bytes(2, "big") + v1
    c2 = b"\x03\x01" + len(v2).to_bytes(2, "big") + v2
    return "\n".join([
        "# B005 v2 signed envelope conformance vectors (barnard issue 122, spec 134 relay)",
        "# Format: see test-vectors/README.md. Hex is lowercase, no 0x.", "#",
        "# Provenance: computed by an independent reference implementation (pure-Python",
        "# secp256k1 + RFC 6979 + low-S), not by the Swift native origin, so the two",
        "# platform implementations are not grading their own homework. That reference",
        "# was first validated against this repository's own committed",
        "# secp256k1-ecdsa-v1.txt vector, reproducing its expected_r, expected_s and",
        "# expected_v exactly. Same rationale as secp256k1-ecdsa-v1.txt itself.", "#",
        "# Every value below is independently recomputable: the key-set digest is a",
        "# SHA-256, the event id is a keccak-256 over a fixed 160-byte preimage, the",
        "# open code is lowercase hex of the event id, the COSE kid is a SHA-256 over a",
        "# domain-prefixed public key, and both signatures verify by public-key",
        "# recovery against keys carried in the envelope.",
        "# Shared fixture identity with levarac/parallax positive/event-definition-v1.json",
        "# and positive/delegation-cert-v1.json: the eventId below is byte-identical to theirs.", "",
        "# --- shared event identity (all recomputable offline) ---",
        "domain_separation_tag=" + data["domain_separation_tag"],
        "registrar=" + data["registrar"], "anchor_operator=" + data["anchor_operator"], "nonce=" + data["nonce"],
        "authority_public_key=" + data["authority_public_key"], "event_key_set_bytes=" + key_set,
        "event_key_set_digest=" + digest, "event_id=" + data["event_id"], "open_code_v1=" + data["event_id"],
        "event_code_hash=" + data["event_code_hash"], "cose_kid_domain=levarac:cose-kid:v1\\0", "cose_kid_authority=f5df3c6eefaf5217", "",
        "# --- vector 1: authority-direct mode (cert_length = 0), hop 0 ---",
        "v1_join_mode=0", "v1_enin_seconds=" + str(data["v1"]["enin_seconds"]),
        "v1_valid_from_enin=" + str(data["v1"]["valid_from_enin"]), "v1_valid_through_enin=" + str(data["v1"]["valid_through_enin"]),
        "v1_relay_expires_at_enin=" + str(data["v1"]["relay_expires_at_enin"]), "v1_display_name=" + data["v1"]["display_name"],
        "v1_display_name_bytes=" + str(len(data["v1"]["display_name"].encode())),
        "v1_signature_digest=" + hashlib.sha256(b"barnard-b005-event-info:v1" + v1[:-65]).hexdigest(),
        "v1_signature_r_s_v=" + data["v1"]["signature"], "v1_envelope=" + v1.hex(), "v1_envelope_length=" + str(len(v1)), "v1_container=" + c1.hex(), "v1_container_length=" + str(len(c1)), "",
        "# --- vector 2: delegate mode, cert byte-identical to the parallax bundle copy, hop 1 ---",
        "v2_delegation_cert=" + data["v2"]["delegation_cert"], "v2_delegation_cert_length=" + str(len(bytes.fromhex(data["v2"]["delegation_cert"]))),
        "v2_delegate_public_key=" + data["v2"]["delegate_public_key"], "v2_display_name=" + data["v2"]["display_name"],
        "v2_display_name_bytes=" + str(len(data["v2"]["display_name"].encode())),
        "v2_signature_digest=" + hashlib.sha256(b"barnard-b005-event-info:v1" + v2[:-65]).hexdigest(),
        "v2_signature_r_s_v=" + data["v2"]["signature"], "v2_envelope=" + v2.hex(), "v2_envelope_length=" + str(len(v2)), "v2_container=" + c2.hex(), "v2_container_length=" + str(len(c2)), "",
        "# --- negative: census v2 payload must not parse as a relay container ---",
        "# Census v2 (specs/123-128) begins 0x02; a relay container begins 0x03. Even if the",
        "# leading byte were accepted, the length field would not end at the value boundary.",
        "neg_census_v2_payload_length=340", "neg_census_v2_prefix=" + data["negative_census_v2_prefix"], "neg_census_v2_expected=reject_format_version", "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = render(json.loads(FIXTURE.read_text()))
    if args.check:
        return 0 if text == TARGET.read_text() else 1
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
