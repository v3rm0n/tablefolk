"""Independent standard-library CBOR/SHA-512/scalar-reduction regression vectors."""
import hashlib
import json
from pathlib import Path

PROFILE = b"bg-ristretto255-36-4x9-fs-candidate-v1"
DOMAIN = b"p2pcards/v1/shuffle"
ORDER = 2**252 + 27742317777372353535851937790883648493

def header(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")

def cbor(value):
    if isinstance(value, int):
        return header(0, value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    return header(4, len(value)) + b"".join(map(cbor, value))

root = bytes(range(32))
context = {"gameId": (bytes([66]) * 16).hex(), "round": 7, "phase": "shuffle-2"}
prefix = DOMAIN + bytes.fromhex(context["gameId"]) + cbor(context["round"]) + header(3, len(context["phase"])) + context["phase"].encode()
events = []
operations = []
challenges = []
for step, (label, challenge, count) in enumerate([
    (b"shuffle_argument", b"x", 1),
    (None, b"yz", 2),
    (b"hadamard_product_argument", b"xy", 2),
    (b"zero_argument", b"x", 1),
    (b"single_value_product_argument", b"x", 1),
    (b"multi-exponentiation", b"x_powers", 1),
]):
    if label:
        events.append([0, label])
        operations.append({"kind": "label", "bytes": label.hex()})
    public = bytes((i + step) % 256 for i in range(32 + step))
    events.append([1, public])
    operations.append({"kind": "append", "bytes": public.hex()})
    operations.append({"kind": "challenge", "bytes": challenge.hex(), "count": count})
    for index in range(count):
        raw = prefix + cbor([PROFILE, root, events, [2, challenge, index]])
        digest = hashlib.sha512(raw).digest()
        scalar = (int.from_bytes(digest, "little") % ORDER).to_bytes(32, "little")
        challenges.append({"input": raw.hex(), "digest": digest.hex(), "scalar": scalar.hex()})
        events.append([2, challenge, index, scalar])

Path(__file__).with_name("shuffle-transcript.json").write_text(
    json.dumps({"context": context, "root": root.hex(), "operations": operations, "challenges": challenges}, indent=2) + "\n"
)
