#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""verify.py: Python twin of verify/verify.mjs (receipt, chain, book, refusal and generation-7 recompute checks).

Independent like verify.mjs: imports nothing from src/ or from the JS. It
reimplements canonical JSON (ECMAScript JSON.stringify semantics), DSSE PAE,
the doctrine checks and the hash-chain walk, and prints the same per-check
lines so both verifiers can be compared on the same inputs.

Usage:
    python verify/verify.py <receipt.json> [more.json ...]
    python verify/verify.py --dir receipts/
    python verify/verify.py --pubkey keys/engine_pubkey.json --dir DIR
    python verify/verify.py --pubkey keys/engine_pubkey.json --chain ledger/
    python verify/verify.py --pubkey keys/engine_pubkey.json --book ledger/
    python verify/verify.py --pubkey keys/engine_pubkey.json --refusals ledger/

Scope: --witness (Rekor, TSA, gossip) is NOT implemented here; verify.mjs
stays authoritative for it. Generation-7 backtest receipts are recomputed
bit-exactly; generation-8 receipts, and grids with non-integer windows, are
reported "recompute: NOT ASSESSED" rather than treated as covered.

Deliberate strictness differences from verify.mjs (reject-only):
- base64 payloads and signatures must be well-formed (validate=True);
- files must be valid UTF-8; JSON NaN/Infinity literals are refused;
- --pubkey pins are checked for kind/alg and keyId self-consistency.
Exit status: 0 iff everything checked verifies, 1 otherwise, 2 on usage or pin error.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys

LOCKED = ["F1", "F11", "F12", "F18", "F19", "F22", "F4", "F7"]  # sorted (UTF-16 order)
CEILING = 0.97
PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO = "https://in-toto.io/Statement/v1"
BACKTEST_PREDICATE_M7 = "https://szl.holdings/quant/backtest/v1"
CHAIN_RE = re.compile(r"chain_[0-9]{4}\.receipt\.json")
_CONJ = re.compile(r"conjecture 1", re.IGNORECASE | re.ASCII)
_THEOREM = re.compile(r"theorem", re.IGNORECASE | re.ASCII)


class _Undefined:
    """JavaScript `undefined` (a missing property), distinct from JSON null (None)."""

    def __repr__(self):
        return "undefined"

    def __bool__(self):
        return False


UNDEF = _Undefined()

# Ed25519 verification hook: (spki_der, signature, message) -> bool.
# Defaults to the `cryptography` package, imported on first use.
ED25519_VERIFY = None


def _default_ed25519_verify(spki_der, signature, message):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key = load_der_public_key(spki_der)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not ed25519")
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed25519_verify(spki_der, signature, message):
    return (ED25519_VERIFY or _default_ed25519_verify)(spki_der, signature, message)


# ---------------------------------------------------------------- JS semantics
def is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def get(obj, key):
    """obj?.[key] on a JSON value; UNDEF when absent or not indexable."""
    if isinstance(obj, dict):
        return obj.get(str(key) if isinstance(key, int) else key, UNDEF)
    if isinstance(obj, (list, str)) and isinstance(key, int):
        return obj[key] if 0 <= key < len(obj) else UNDEF
    return UNDEF


def nullish(v):
    return v is None or v is UNDEF


def coalesce(*values):
    for v in values:
        if not nullish(v):
            return v
    return values[-1]


def truthy(v):
    if v is None or v is UNDEF or v is False:
        return False
    if is_number(v):
        return v != 0 and v == v
    if isinstance(v, str):
        return v != ""
    return True


def _js_number_digits(x):
    """Shortest round-trip digits s and exponent n with x = 0.s * 10**n (x > 0)."""
    r = repr(float(x))
    mant, _, exp = r.partition("e")
    exp = int(exp) if exp else 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead = len(ip.lstrip("0")) if ip.strip("0") else -(len(fp) - len(fp.lstrip("0")))
    n = lead + exp
    return digits.rstrip("0"), n


def js_number(v):
    """ECMAScript Number::toString for a JSON-decoded number (as JSON.stringify prints it)."""
    if is_number(v) and isinstance(v, int):
        try:
            v = float(v)
        except OverflowError:
            raise ValueError("non-finite") from None
    x = float(v)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + js_number(-x)
    s, n = _js_number_digits(x)
    k = len(s)
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    sign = "+" if e >= 0 else "-"
    return (s if k == 1 else s[0] + "." + s[1:]) + "e" + sign + str(abs(e))


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def js_string_literal(s):
    """JSON.stringify(string): well-formed JSON.stringify (ES2019) escaping."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def canonicalize(v):
    """Twin of verify.mjs canonicalize(): recursively key-sorted JSON, no spaces."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_number(v):
        return js_number(v)
    if isinstance(v, str):
        return js_string_literal(v)
    if isinstance(v, list):
        return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=utf16_key)
        return "{" + ",".join(js_string_literal(k) + ":" + canonicalize(v[k]) for k in keys) + "}"
    raise ValueError(f"bad type {type(v).__name__}")


def js_to_string(v):
    """ECMAScript String(v) for JSON values (also used by template literals)."""
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_number(v):
        return js_number(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return ",".join("" if nullish(x) else js_to_string(x) for x in v)
    return "[object Object]"


_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def js_entries(obj):
    """Object.entries order: array-index keys ascending, then insertion order."""
    if isinstance(obj, list):
        return [(str(i), x) for i, x in enumerate(obj)]
    idx = [k for k in obj if _ARRAY_INDEX.fullmatch(k) and int(k) < 2**32 - 1]
    rest = [k for k in obj if k not in set(idx)]
    return [(k, obj[k]) for k in sorted(idx, key=int) + rest]


def js_sort(values):
    """Array.prototype.sort() with no comparator: ToString + UTF-16 order, undefined last."""
    defined = [v for v in values if v is not UNDEF]
    undef = [v for v in values if v is UNDEF]
    return sorted(defined, key=lambda v: utf16_key(js_to_string(v))) + undef


def js_iterate(v):
    """for-of over a JSON value; strings iterate by code point; others are not iterable."""
    if isinstance(v, list):
        return list(v)
    if isinstance(v, str):
        return list(v)
    raise TypeError("value is not iterable")


def _no_constants(name):
    raise ValueError(f"invalid JSON literal {name}")


def json_loads(text):
    return json.loads(text, parse_constant=_no_constants)


def b64_strict(v):
    if not isinstance(v, str):
        raise ValueError("not a string")
    return base64.b64decode(v, validate=True)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def pae(t, body):
    tb = t.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(tb), tb, len(body)) + body


# -------------------------------------------------------------------- receipts
def walk_convictions(node, path="$"):
    if isinstance(node, (dict, list)):
        for k, v in js_entries(node):
            if k in ("conviction", "confidence", "trust") and is_number(v):
                yield path + "." + k, v
            yield from walk_convictions(v, f"{path}.{k}")


def load_pin(path):
    """Read an engine pin; returns SPKI DER. Raises ValueError (exit 2)."""
    with open(path, "rb") as fh:
        pin = json_loads(fh.read().decode("utf-8"))
    if not isinstance(pin, dict) or pin.get("alg") != "ed25519" or pin.get("kind") != "szl-quant-engine-pubkey":
        raise ValueError("pin is not an szl-quant-engine-pubkey ed25519 pin")
    der = b64_strict(pin.get("publicKeySpkiBase64"))
    if not isinstance(pin.get("keyId"), str) or sha256_hex(der)[:16] != pin["keyId"]:
        raise ValueError("pin keyId does not match sha256(SPKI)[:16]")
    return der


def verify_file(path, pinned_der):
    """Twin of verifyFile(). Returns {file, ok, fails, notes, keyid?}."""
    fails, notes = [], []
    try:
        with open(path, "rb") as fh:
            env = json_loads(fh.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {"file": path, "ok": False, "fails": [f"unreadable JSON: {exc}"], "notes": []}
    try:
        return _verify_env(path, env, pinned_der, fails, notes)
    except (TypeError, ValueError, AttributeError, binascii.Error) as exc:
        fails.append(f"verifier error (verify.mjs would throw here): {exc}")
        return {"file": path, "ok": False, "fails": fails, "notes": notes}


def _verify_env(path, env, pinned_der, fails, notes):
    ptype = get(env, "payloadType")
    if ptype != PAYLOAD_TYPE:
        fails.append(f"payloadType {js_to_string(ptype)}")
    payload = None
    try:
        payload = b64_strict(get(env, "payload"))
    except (ValueError, binascii.Error):
        fails.append("payload not base64")
    pub = pinned_der
    if pub is None and truthy(get(env, "publicKeySpkiBase64")):
        pub = b64_strict(get(env, "publicKeySpkiBase64"))
        notes.append("TOFU: verified against envelope-embedded key (pin with --pubkey for stronger trust)")
    if pub is None:
        fails.append("no public key")
        return {"file": path, "ok": False, "fails": fails, "notes": notes}
    keyid = sha256_hex(pub)[:16]
    sigs = coalesce(get(env, "signatures"), [])
    if not isinstance(sigs, list):
        raise TypeError("signatures is not an array")
    entry = UNDEF
    for s in sigs:  # Array.prototype.find: stops at the first match, throws on null
        if s is None:
            raise TypeError("Cannot read properties of null (reading 'keyid')")
        if get(s, "keyid") == keyid:
            entry = s
            break
    if entry is UNDEF:
        fails.append(f"no signature for keyid {keyid}")
    if entry is not UNDEF and payload is not None:
        ok = ed25519_verify(pub, b64_strict(get(entry, "sig")), pae(ptype if isinstance(ptype, str) else js_to_string(ptype), payload))
        if not ok:
            fails.append("ed25519 signature INVALID over PAE")
    st = UNDEF
    if payload is not None:
        try:
            st = json_loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            fails.append("payload not JSON")
            st = UNDEF
    if truthy(st):
        if get(st, "_type") != IN_TOTO:
            fails.append(f"statement _type {js_to_string(get(st, '_type'))}")
        pred = get(st, "predicate")
        d = get(pred, "_doctrine")
        if not truthy(d):
            fails.append("missing _doctrine block")
        else:
            if get(get(d, "posture"), "mode") != "ADVISORY_PAPER_ONLY":
                fails.append("posture not ADVISORY_PAPER_ONLY")
            if get(get(d, "posture"), "provenTrust") is not False:
                fails.append("provenTrust not locked false")
            tc = get(d, "trustCeiling")
            if not (is_number(tc) and tc == CEILING):
                fails.append(f"trustCeiling {js_to_string(tc)} \u2260 {js_number(CEILING)}")
            locked = js_sort(js_iterate(coalesce(get(d, "lockedProvenFormulaIds"), [])))
            if not (all(isinstance(x, str) for x in locked) and locked == LOCKED):
                fails.append("locked-proven set not EXACTLY the canonical 8")
            lam = js_to_string(coalesce(get(d, "lambdaStatus"), ""))
            if not _CONJ.search(lam):
                fails.append('\u039b status missing "Conjecture 1"')
            if _THEOREM.search(lam):
                fails.append('\u039b status claims "theorem" \u2014 doctrine violation')
        for p, v in walk_convictions(pred):
            if v > CEILING:
                fails.append(f"{p} = {js_number(v)} exceeds trust ceiling {js_number(CEILING)}")
        dec = coalesce(get(pred, "decision"), get(pred, "summary"), None)
        digest = get(get(get(get(st, "subject"), 0), "digest"), "sha256")
        if truthy(dec) and truthy(digest):
            recomputed = sha256_hex(canonicalize(dec).encode("utf-8"))
            if recomputed != digest:
                fails.append("subject digest \u2260 sha256(canonical(decision))")
        elif not truthy(digest):
            fails.append("missing subject digest")
        gates = js_iterate(coalesce(get(dec, "gates"), []))
        for g in gates:
            if g is None:
                raise TypeError("Cannot read properties of null (reading 'verdict')")
            gv = get(g, "verdict")
            if gv != "ALLOWED" and gv != "BLOCKED":
                fails.append(f"gate {js_to_string(get(g, 'gate'))} has non-canon verdict {js_to_string(gv)}")
        if get(dec, "verdict") == "BLOCKED":
            blocking = [g for g in gates if get(g, "verdict") == "BLOCKED"]
            if not blocking:
                fails.append("verdict BLOCKED but no blocking gate listed")
            if any(not truthy(get(g, "reason")) for g in blocking):
                fails.append("blocking gate missing honest reason")
    return {"file": path, "ok": not fails, "fails": fails, "notes": notes, "keyid": keyid}



# ----------------------------------------------------------------------- chain
def _entries(path):
    with os.scandir(path) as it:
        return list(it)


def _is_integer(v):
    """Number.isInteger on a JSON-decoded value."""
    if not is_number(v):
        return False
    if isinstance(v, int):
        return True
    return v == v and v not in (float("inf"), float("-inf")) and v.is_integer()


def _map_key(v):
    try:
        hash(v)
        return ("v", type(v).__name__ if not isinstance(v, (int, float)) or isinstance(v, bool) else "num", v)
    except TypeError:
        return ("obj", id(v))


def verify_chain(ledger_dir, pinned_der, out=print):
    """Twin of verifyChain(). Prints the same lines; returns True iff the chain holds."""
    try:
        dirs = sorted((e.name for e in _entries(ledger_dir) if e.is_dir(follow_symlinks=False)), key=utf16_key)
    except OSError as exc:
        out(f"CHAIN FAIL: cannot read {ledger_dir}: {exc}")
        return False
    problems, links, dir_files = [], [], {}
    for d in dirs:
        names = sorted((e.name for e in _entries(os.path.join(ledger_dir, d)) if e.is_file(follow_symlinks=False)), key=utf16_key)
        dir_files[d] = [n for n in names if n.endswith(".json") and not CHAIN_RE.fullmatch(n)]
        chain_files = [n for n in names if CHAIN_RE.fullmatch(n)]
        if len(chain_files) > 1:
            problems.append(f"{d}: {len(chain_files)} chain receipts in one dir (ambiguous)")
        for cf in chain_files:
            full = os.path.join(ledger_dir, d, cf)
            r = verify_file(full, pinned_der)
            if not r["ok"]:
                problems.append(f"{d}/{cf}: link receipt fails verification: {'; '.join(r['fails'])}")
            body = UNDEF
            try:
                with open(full, "rb") as fh:
                    raw = fh.read()
                env = json_loads(raw.decode("utf-8"))
                body = coalesce(get(get(json_loads(base64.b64decode(get(env, "payload")).decode("utf-8")), "predicate"), "summary"), None)
            except Exception:
                body = UNDEF
            if not truthy(body) or not _is_integer(get(body, "seq")):
                problems.append(f"{d}/{cf}: unreadable chain body")
                continue
            links.append({"dir": d, "file": cf, "body": body, "sha256": sha256_hex(raw)})
    if not links:
        out("CHAIN FAIL: no chain receipts found under " + ledger_dir)
        return False
    links.sort(key=lambda l: l["body"]["seq"])
    for i, l in enumerate(links):
        if l["body"]["seq"] != i + 1:
            problems.append(f"seq not contiguous: expected {i + 1}, found {js_number(l['body']['seq'])} ({l['dir']}/{l['file']})")
    if get(links[0]["body"], "prev") is not None:
        problems.append(f"first link ({links[0]['dir']}/{links[0]['file']}) is not genesis: prev \u2260 null")
    for i in range(1, len(links)):
        prev = get(links[i]["body"], "prev")
        seq = js_number(links[i]["body"]["seq"])
        if not truthy(prev):
            problems.append(f"seq {seq}: missing prev pointer")
            continue
        if get(prev, "sha256") != links[i - 1]["sha256"] or get(prev, "file") != links[i - 1]["file"] or get(prev, "runDir") != links[i - 1]["dir"]:
            problems.append(f"seq {seq}: prev pointer mismatch \u2014 chain BROKEN between {links[i - 1]['dir']} and {links[i]['dir']}")
    covered = {}
    for l in links:
        for cov in js_iterate(coalesce(get(l["body"], "covers"), [])):
            if cov is None:
                raise TypeError("Cannot read properties of null (reading 'dir')")
            key = _map_key(get(cov, "dir"))
            if key in covered:
                problems.append(f"dir {js_to_string(get(cov, 'dir'))} sealed twice (seq {js_number(covered[key]['seq'])} and {js_number(l['body']['seq'])})")
            else:
                covered[key] = {"dir": get(cov, "dir"), "files": coalesce(get(cov, "files"), []), "seq": l["body"]["seq"]}
    for d in dirs:
        if _map_key(d) not in covered:
            problems.append(f"dir {d} NOT sealed by any chain link")
    for cov in covered.values():
        d = cov["dir"]
        if not (isinstance(d, str) and d in dirs):
            problems.append(f"sealed dir {js_to_string(d)} MISSING from ledger (deleted after sealing)")
            continue
        on_disk = dir_files[d]
        if not isinstance(cov["files"], list):
            raise TypeError("cov.files.map is not a function")
        if any(f is None for f in cov["files"]):
            raise TypeError("Cannot read properties of null (reading 'name')")
        listed = js_sort([get(f, "name") for f in cov["files"]])
        if not (all(isinstance(x, str) for x in listed) and listed == on_disk):
            problems.append(f"dir {d}: file set mismatch \u2014 on disk [{', '.join(on_disk)}] vs sealed [{', '.join('' if nullish(x) else js_to_string(x) for x in listed)}]")
        for f in cov["files"]:
            name = get(f, "name")
            if not (isinstance(name, str) and name in on_disk):
                continue
            with open(os.path.join(ledger_dir, d, name), "rb") as fh:
                if sha256_hex(fh.read()) != get(f, "sha256"):
                    problems.append(f"{d}/{name}: sha256 mismatch \u2014 file REWRITTEN after sealing")
    for p in problems:
        out(f"      CHAIN FAIL: {p}")
    head = links[-1]
    if not problems:
        files_sealed = sum(len(c["files"]) for c in covered.values())
        out(f"CHAIN OK  links={len(links)}  head=seq {js_number(head['body']['seq'])} sha256={head['sha256'][:12]}\u2026  dirs sealed={len(covered)}  files sealed={files_sealed}")
        out("      note: honest limit \u2014 wholesale deletion of the newest link(s) needs external witnesses (Actions logs, INDEX git history)")
        return True
    out("CHAIN BROKEN")
    return False


# ------------------------------------------------------------------------ book
BOOK_RE = re.compile(r"book_[0-9]+\.receipt\.json")
MICRO_B = 1_000_000
QTY_B = 1_000_000_000


class JsThrow(Exception):
    """An error verify.mjs throws inside its try block; the message mirrors V8's."""


def js_to_fixed(x, digits):
    """Number.prototype.toFixed: exact binary value, ties away from zero (larger n)."""
    import decimal
    x = float(x)
    if abs(x) >= 1e21:
        return js_number(x)
    neg = x < 0  # -0 is not < 0
    with decimal.localcontext() as ctx:
        ctx.prec = 200
        q = decimal.Decimal(abs(x)).quantize(decimal.Decimal(1).scaleb(-digits), rounding=decimal.ROUND_HALF_UP)
    out = format(q, "f")
    return ("-" if neg else "") + out


_JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def js_bigint(v):
    """BigInt(v) for JSON values; raises JsThrow with V8's message."""
    if v is True or v is False:
        return 1 if v else 0
    if is_number(v):
        if isinstance(v, int):
            return v
        if v != v or v in (float("inf"), float("-inf")) or not v.is_integer():
            raise JsThrow(f"The number {js_number(v) if v == v and abs(v) != float('inf') else ('NaN' if v != v else ('Infinity' if v > 0 else '-Infinity'))} cannot be converted to a BigInt because it is not an integer")
        return int(v)
    if v is None or v is UNDEF:
        raise JsThrow(f"Cannot convert {js_to_string(v)} to a BigInt")
    text = js_to_string(v)
    t = text.strip(_JS_WS)
    if t == "":
        return 0
    if re.fullmatch(r"[+-]?[0-9]+", t):
        return int(t)
    m = re.fullmatch(r"0([xXoObB])([0-9a-fA-F]+)", t)
    if m:
        base = {"x": 16, "o": 8, "b": 2}[m.group(1).lower()]
        try:
            return int(m.group(2), base)
        except ValueError:
            pass
    raise JsThrow(f"Cannot convert {text} to a BigInt")


def tdiv(a, b):
    """BigInt division: truncates toward zero; RangeError on zero."""
    if b == 0:
        raise JsThrow("Division by zero")
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def to_micro(x):
    """Twin of toMicroB()."""
    if not is_number(x) or not math.isfinite(float(x)):
        raise JsThrow("non-finite amount")
    s = js_to_fixed(x, 6)
    neg = s.startswith("-")
    parts = (s[1:] if neg else s).split(".")
    ints = parts[0]
    fracs = parts[1] if len(parts) > 1 else UNDEF
    v = js_bigint(ints) * MICRO_B + js_bigint(fracs)
    return -v if neg else v


def micro_str(m):
    neg = m < 0
    a = -m if neg else m
    return f"{'-' if neg else ''}{a // MICRO_B}.{str(a % MICRO_B).rjust(6, '0')}"


def js_gt0(v):
    return js_less(0, v)


def js_mul(a, b):
    return _js_to_number(a) * b


def _symbol_cmp(a, b):
    return -1 if js_less(a["symbol"], b["symbol"]) else (1 if js_less(b["symbol"], a["symbol"]) else 0)


def book_decision_mirror(name, st):
    """Twin of decisionFromStatement()."""
    dec = get(get(st, "predicate"), "decision")
    if not truthy(get(get(dec, "asset"), "symbol")) or not truthy(get(dec, "proposedAction")) or not truthy(get(dec, "verdict")):
        return None
    snap = get(dec, "snapshot")
    return {"file": name, "symbol": get(get(dec, "asset"), "symbol"), "proposedAction": get(dec, "proposedAction"),
            "verdict": get(dec, "verdict"), "priceUsd": coalesce(get(snap, "priceUsd"), None),
            "observedAtIso": coalesce(get(snap, "observedAtIso"), None)}


def _js_entries_any(v):
    if isinstance(v, (dict, list)):
        return js_entries(v)
    if isinstance(v, str):
        return [(str(i), ch) for i, ch in enumerate(v)]
    return []


def replay_transition(start_state, config, decisions, generated_at):
    """Byte-exact twin of replayTransition() (frozen v1 book rules)."""
    cm = get(config, "costModel")
    fee, slip = get(cm, "feeBps"), get(cm, "slippageBps")
    cost_rate = (float(fee) + float(slip)) / 10_000
    cash = start_state["cashMicro"]
    positions = {}
    for a, p in js_entries(start_state["positions"]):
        positions[a] = {"qtyE9": p["qtyE9"], "costMicro": p["costMicro"]}
    fills, no_actions = [], []
    ordered = _js_stable_sort(decisions, _symbol_cmp)
    prices = {}
    for d in ordered:
        if js_gt0(d["priceUsd"]):
            prices[js_to_string(d["symbol"])] = d["priceUsd"]

    def equity_now():
        eq = cash
        for asset, p in js_entries(positions):
            if p["qtyE9"] == 0:
                continue
            price = prices.get(asset, UNDEF)
            if not js_gt0(price):
                return None
            eq += tdiv(p["qtyE9"] * to_micro(price), QTY_B)
        return eq

    cost_model = lambda: {"feeBps": fee, "slippageBps": slip, "label": "MODELED"}  # noqa: E731
    for d in ordered:
        key = js_to_string(d["symbol"])
        pos = positions.get(key)
        held = pos is not None and pos["qtyE9"] > 0
        if d["verdict"] != "ALLOWED":
            no_actions.append({"asset": d["symbol"], "action": "NONE", "why": f"decision {js_to_string(d['verdict'])} \u2014 fail closed, the gates hold the book"})
            continue
        if d["proposedAction"] == "ENTER_LONG":
            if held:
                no_actions.append({"asset": d["symbol"], "action": "NONE", "why": "already long \u2014 no pyramiding in v1"})
                continue
            if not js_gt0(d["priceUsd"]):
                no_actions.append({"asset": d["symbol"], "action": "NONE", "why": "no observed price \u2014 cannot fill honestly (fail closed)"})
                continue
            eq = equity_now()
            if eq is None:
                no_actions.append({"asset": d["symbol"], "action": "NONE", "why": "an open position is unpriced \u2014 equity not computable, no new entries (fail closed)"})
                continue
            alloc = tdiv(eq * js_bigint(get(config, "entryFractionBps")), 10_000)
            if alloc <= 0 or alloc > cash:
                no_actions.append({"asset": d["symbol"], "action": "SKIPPED_INSUFFICIENT_CASH",
                                   "why": f"entry needs {micro_str(alloc)} USD but paper cash is {micro_str(cash)} \u2014 no leverage, honest skip"})
                continue
            price = d["priceUsd"]
            notional = to_micro(float(micro_str(alloc)))
            eff = js_mul(price, 1 + cost_rate)
            qty = tdiv(notional * QTY_B, to_micro(eff))
            gross = tdiv(notional * QTY_B, to_micro(price))
            modeled = tdiv((gross - qty) * to_micro(price), QTY_B)
            cur = positions.get(key) or {"qtyE9": 0, "costMicro": 0}
            cash -= notional
            cur["qtyE9"] += qty
            cur["costMicro"] += notional
            positions[key] = cur
            fills.append({"asset": d["symbol"], "side": "BUY", "notionalUsd": micro_str(notional), "price": js_to_string(price),
                          "effectivePrice": js_to_fixed(eff, 10), "qtyE9": str(qty), "modeledCostUsd": micro_str(modeled),
                          "costModel": cost_model(), "atIso": d["observedAtIso"], "reason": "ALLOWED ENTER_LONG"})
        elif d["proposedAction"] == "EXIT_LONG":
            if not held:
                no_actions.append({"asset": d["symbol"], "action": "NONE", "why": "no open position to exit"})
                continue
            if not js_gt0(d["priceUsd"]):
                no_actions.append({"asset": d["symbol"], "action": "NONE", "why": "no observed price \u2014 cannot exit honestly (fail closed, position remains)"})
                continue
            price = d["priceUsd"]
            q = positions[key]["qtyE9"]
            eff = js_mul(price, 1 - cost_rate)
            proceeds = tdiv(q * to_micro(eff), QTY_B)
            gross = tdiv(q * to_micro(price), QTY_B)
            cash += proceeds
            positions[key]["qtyE9"] -= q
            if positions[key]["qtyE9"] == 0:
                positions[key]["costMicro"] = 0
            fills.append({"asset": d["symbol"], "side": "SELL", "notionalUsd": micro_str(proceeds), "price": js_to_string(price),
                          "effectivePrice": js_to_fixed(eff, 10), "qtyE9": str(q), "modeledCostUsd": micro_str(gross - proceeds),
                          "costModel": cost_model(), "atIso": d["observedAtIso"], "reason": "ALLOWED EXIT_LONG"})
        else:
            no_actions.append({"asset": d["symbol"], "action": "NONE", "why": f"{js_to_string(d['proposedAction'])} \u2014 no book action"})
    positions_out, equity, unpriced = [], cash, 0
    for asset, pos in js_entries(positions):
        if pos["qtyE9"] == 0:
            continue
        p = prices.get(asset, UNDEF)
        if not js_gt0(p):
            positions_out.append({"asset": asset, "qtyE9": str(pos["qtyE9"]), "value": {"label": "UNAVAILABLE", "note": "no observed price at mark time"}})
            unpriced += 1
            continue
        value = tdiv(pos["qtyE9"] * to_micro(p), QTY_B)
        equity += value
        positions_out.append({"asset": asset, "qtyE9": str(pos["qtyE9"]), "markPrice": js_to_string(p), "valueUsd": micro_str(value)})
    mark = {"cashUsd": micro_str(cash), "positions": positions_out, "equityUsd": micro_str(equity) if unpriced == 0 else None, "fillsSoFar": len(fills)}
    if generated_at is not UNDEF:
        mark["atIso"] = generated_at
    if unpriced:
        mark["equityNote"] = f"{unpriced} position(s) unpriced \u2014 equity not computable (honest empty)"
    state_positions = {a: {"qtyE9": str(p["qtyE9"]), "costMicro": str(p["costMicro"])} for a, p in js_entries(positions) if p["qtyE9"] > 0}
    return {"fills": fills, "noActions": no_actions, "state": {"cashMicro": str(cash), "positions": state_positions}, "mark": mark, "sortedDecisions": ordered}


def _js_finite(v):
    return is_number(v) and math.isfinite(float(v))


def _js_length(v):
    if isinstance(v, list):
        return len(v)
    if isinstance(v, str):
        return len(v.encode("utf-16-le", "surrogatepass")) // 2
    return get(v, "length") if isinstance(v, dict) else UNDEF


def verify_book(ledger_dir, pinned_der, out=print):
    """Twin of verifyBook(): chain structure, gap honesty, and byte-exact replay of every link."""
    try:
        dirs = sorted((e.name for e in _entries(ledger_dir) if e.is_dir(follow_symlinks=False)), key=utf16_key)
    except OSError as exc:
        out(f"BOOK FAIL: cannot read {ledger_dir}: {exc}")
        return False
    problems, links = [], []
    for d in dirs:
        names = sorted((e.name for e in _entries(os.path.join(ledger_dir, d)) if e.is_file(follow_symlinks=False)), key=utf16_key)
        bfs = [n for n in names if BOOK_RE.fullmatch(n)]
        if len(bfs) > 1:
            problems.append(f"{d}: {len(bfs)} book receipts in one dir (ambiguous)")
        for bf in bfs:
            full = os.path.join(ledger_dir, d, bf)
            r = verify_file(full, pinned_der)
            if not r["ok"]:
                problems.append(f"{d}/{bf}: book receipt fails verification: {'; '.join(r['fails'])}")
            body = _summary_of(full)
            if not truthy(body) or not _is_integer(get(body, "seq")):
                problems.append(f"{d}/{bf}: unreadable book body")
                continue
            with open(full, "rb") as fh:
                raw = fh.read()
            links.append({"dir": d, "file": bf, "body": body, "sha256": sha256_hex(raw)})
    if not links:
        out("BOOK FAIL: no book receipts found under " + ledger_dir)
        return False
    links.sort(key=lambda l: float(l["body"]["seq"]))
    for i, l in enumerate(links):
        if l["body"]["seq"] != i + 1:
            problems.append(f"seq not contiguous: expected {i + 1}, found {js_number(l['body']['seq'])} ({l['dir']}/{l['file']})")
    if get(links[0]["body"], "prev") is not None:
        problems.append(f"first book ({links[0]['dir']}/{links[0]['file']}) is not genesis: prev \u2260 null")
    for l in links:
        if get(l["body"], "runDir") != l["dir"]:
            problems.append(f"seq {js_number(l['body']['seq'])}: body.runDir {js_to_string(get(l['body'], 'runDir'))} \u2260 actual dir {l['dir']}")
    for i in range(1, len(links)):
        seq = js_number(links[i]["body"]["seq"])
        prev = get(links[i]["body"], "prev")
        if not truthy(prev):
            problems.append(f"seq {seq}: missing prev pointer")
            continue
        if get(prev, "sha256") != links[i - 1]["sha256"] or get(prev, "file") != links[i - 1]["file"] or get(prev, "runDir") != links[i - 1]["dir"]:
            problems.append(f"seq {seq}: prev pointer mismatch \u2014 book chain BROKEN between {links[i - 1]['dir']} and {links[i]['dir']}")
        if not utf16_key(links[i]["dir"]) > utf16_key(links[i - 1]["dir"]):
            problems.append(f"seq {seq}: run dir {links[i]['dir']} not after {links[i - 1]['dir']}")
        if canonicalize(get(links[i]["body"], "config")) != canonicalize(get(links[i - 1]["body"], "config")):
            problems.append(f"seq {seq}: config drifted from previous link (must be inherited unchanged)")
    expect_pre = [d for d in dirs if utf16_key(d) < utf16_key(links[0]["dir"])]
    if canonicalize(coalesce(get(links[0]["body"], "preBookRunDirs"), None)) != canonicalize(expect_pre):
        problems.append(f"genesis preBookRunDirs do not match the ledger (expected [{', '.join(expect_pre)}])")
    for i in range(1, len(links)):
        lo, hi = utf16_key(links[i - 1]["dir"]), utf16_key(links[i]["dir"])
        expect_skip = [d for d in dirs if lo < utf16_key(d) < hi]
        if canonicalize(coalesce(get(links[i]["body"], "skippedRunDirs"), None)) != canonicalize(expect_skip):
            problems.append(f"seq {js_number(links[i]['body']['seq'])}: skippedRunDirs do not match the ledger (expected [{', '.join(expect_skip)}])")
    for i, l in enumerate(links):
        body, seq = l["body"], js_number(l["body"]["seq"])
        cfg = get(body, "config")
        cm = get(cfg, "costModel")
        if (not truthy(cm) or not _js_finite(get(cm, "feeBps")) or not _js_finite(get(cm, "slippageBps"))
                or not _js_finite(get(cfg, "entryFractionBps")) or not js_gt0(get(cfg, "startingCashUsd"))):
            problems.append(f"seq {seq}: config incomplete \u2014 cannot replay")
            continue
        rdir = os.path.join(ledger_dir, l["dir"])
        sig_names = sorted((e.name for e in _entries(rdir) if e.is_file(follow_symlinks=False)
                            and e.name.startswith("signal_") and e.name.endswith(".receipt.json")), key=utf16_key)
        decisions, excluded = [], []
        for n in sig_names:
            if not verify_file(os.path.join(rdir, n), pinned_der)["ok"]:
                excluded.append(n)
                continue
            try:
                st = _statement_of(os.path.join(rdir, n))
            except Exception:
                excluded.append(n)
                continue
            dec = book_decision_mirror(n, st)
            if dec is not None:
                decisions.append(dec)
        # Outside verify.mjs's try block: a malformed start state throws and aborts the run.
        if body["seq"] == 1:
            start = {"cashMicro": to_micro(get(cfg, "startingCashUsd")), "positions": {}}
        else:
            if i == 0:
                raise TypeError("Cannot read properties of undefined (reading 'body')")
            prev_body = links[i - 1]["body"]
            positions = {}
            for a, p in _js_entries_any(coalesce(get(get(prev_body, "state"), "positions"), {})):
                if p is None or p is UNDEF:
                    raise TypeError("Cannot read properties of null (reading 'qtyE9')")
                positions[a] = {"qtyE9": js_bigint(get(p, "qtyE9")), "costMicro": js_bigint(get(p, "costMicro"))}
            state = get(prev_body, "state")
            if state is None or state is UNDEF:
                raise TypeError("Cannot read properties of undefined (reading 'cashMicro')")
            start = {"cashMicro": js_bigint(get(state, "cashMicro")), "positions": positions}
        try:
            rep = replay_transition(start, cfg, decisions, get(body, "generatedAtIso"))
        except JsThrow as exc:
            problems.append(f"seq {seq}: replay threw \u2014 {exc}")
            continue
        expect_inputs = {
            "signalFiles": sorted((d["file"] for d in rep["sortedDecisions"]), key=utf16_key),
            "decisions": [{k: d[k] for k in ("file", "symbol", "proposedAction", "verdict", "priceUsd", "observedAtIso")} for d in rep["sortedDecisions"]],
            "excludedSignals": {"count": len(excluded), "files": sorted(excluded, key=utf16_key)},
        }
        checks = (("inputs", expect_inputs, "inputs do not match the verified signal receipts on disk \u2014 book misrepresents its inputs"),
                  ("fills", rep["fills"], "fills do not REPLAY from the signed decisions (recomputed fills differ)"),
                  ("noActions", rep["noActions"], "noActions do not replay (fail-closed notes differ)"),
                  ("state", rep["state"], "end state does not replay \u2014 cash/positions REWRITTEN or miscomputed"),
                  ("mark", rep["mark"], "mark-to-market does not replay \u2014 equity cannot be trusted"))
        for field, expect, message in checks:
            if canonicalize(coalesce(get(body, field), None)) != canonicalize(expect):
                problems.append(f"seq {seq}: {message}")
    for p in problems:
        out(f"      BOOK FAIL: {p}")
    if not problems:
        head = links[-1]["body"]
        mark = get(head, "mark")
        eq = get(mark, "equityUsd")
        eq_txt = "UNAVAILABLE (honest empty)" if nullish(eq) else "$" + js_to_string(eq)
        open_n = _js_length(coalesce(get(mark, "positions"), []))
        out(f"BOOK OK  links={len(links)}  head=seq {js_number(head['seq'])}  equity={eq_txt} [MODELED]  open={js_to_string(open_n)}  cash=${js_to_string(get(mark, 'cashUsd'))}")
        out("      note: every fill, state and mark recomputed from DSSE-verified signal receipts alone \u2014 paper simulation, NOT real funds")
        return True
    out("BOOK BROKEN")
    return False


# -------------------------------------------------- generation-7 recompute
# Twin of verify.mjs recomputeBacktest() for walk-forward replay version 7
# (replay.version absent or 7). Every value that reaches the output comes
# from + - * /, floor, max, sqrt and integer micro-units, which IEEE-754
# makes bit-identical when the operation order is identical. Math.log feeds
# only a null check (annualizedVol), so its last-bit behaviour cannot reach
# a result. Generation 8 is reported NOT ASSESSED: no published receipt uses
# it, so nothing here could prove a twin of it.

class _Unsupported(Exception):
    """Inputs outside what the twin mirrors; reported, never treated as verified."""


def _m7_param(params, key, integer):
    v = get(params, key)
    if not is_number(v) or not math.isfinite(float(v)) or (integer and not float(v).is_integer()):
        raise _Unsupported(f"grid parameter {key} is not a finite {'integer' if integer else 'number'}")
    return int(v) if integer else float(v)


def mean_std_m7(xs):
    if len(xs) < 2:
        return None
    acc = 0
    for b in xs:
        acc = acc + b
    m = acc / len(xs)
    acc = 0
    for b in xs:
        acc = acc + (b - m) * (b - m)
    return {"mean": m, "std": math.sqrt(acc / len(xs))}


def period_return_m7(closes, lookback):
    if len(closes) < lookback + 1:
        return None
    now, then = closes[-1], closes[len(closes) - 1 - lookback]
    if not then > 0 or not math.isfinite(now):
        return None
    return now / then - 1


def z_score_m7(closes, window):
    if len(closes) < window + 1:
        return None
    win = closes[max(len(closes) - window - 1, 0):len(closes) - 1]
    ms = mean_std_m7(win)
    if ms is None or not ms["std"] > 0:
        return None
    return (closes[-1] - ms["mean"]) / ms["std"]


def annualized_vol_is_null_m7(closes, window):
    """annualizedVolM7(...) === null. Its value is never used by the action path."""
    tail = closes[max(len(closes) - (window + 1), 0):]
    for i in range(1, len(tail)):
        if not tail[i - 1] > 0 or not tail[i] > 0:
            return True
    return len(tail) - 1 < 2


def evaluate_action_m7(closes, p):
    mom = period_return_m7(closes, p["momentumLookback"])
    z = z_score_m7(closes, p["zWindow"])
    if mom is None or z is None or annualized_vol_is_null_m7(closes, p["volWindow"]):
        return "ABSTAIN"
    if mom > 0 and z <= -p["zEntry"]:
        return "ENTER_LONG"
    if mom > 0 and abs(z) < p["zEntry"]:
        return "ENTER_LONG"
    if z >= 0 and mom <= 0:
        return "EXIT_LONG"
    return "HOLD"


def _paper_fill_m7(book, side, price, notional_usd=None, qty=None):
    if not price > 0:
        raise JsThrow("fill requires observed price > 0")
    cost_rate = (book["fee"] + book["slip"]) / 10_000
    pos = book["positions"].get("ASSET") or {"qtyE9": 0, "costMicro": 0}
    if side == "BUY":
        if not notional_usd > 0:
            raise JsThrow("BUY requires notionalUsd > 0")
        n = to_micro(notional_usd)
        if book["cash"] < n:
            raise JsThrow("insufficient paper cash (no leverage in paper book)")
        q = tdiv(n * QTY_B, to_micro(price * (1 + cost_rate)))
        book["cash"] -= n
        pos["qtyE9"] += q
        pos["costMicro"] += n
    else:
        if not qty > 0:
            raise JsThrow("SELL requires qtyE9 > 0")
        if pos["qtyE9"] < qty:
            raise JsThrow("insufficient paper position (no shorting in v1 paper book)")
        book["cash"] += tdiv(qty * to_micro(price * (1 - cost_rate)), QTY_B)
        pos["qtyE9"] -= qty
        if pos["qtyE9"] == 0:
            pos["costMicro"] = 0
    book["positions"]["ASSET"] = pos


def _equity_str_m7(book, price):
    eq = book["cash"]
    pos = book["positions"].get("ASSET")
    if pos and pos["qtyE9"] != 0:
        if not price > 0:
            return None
        eq += tdiv(pos["qtyE9"] * to_micro(price), QTY_B)
    return micro_str(eq)


def count_round_trips_m7(trades):
    """(roundTrips, wins) over consecutive BUY/SELL pairs; a win needs exit price > entry price."""
    wins = rts = 0
    for k in range(0, len(trades) - 1, 2):
        if trades[k][0] == "BUY" and trades[k + 1][0] == "SELL":
            rts += 1
            if trades[k + 1][1] > trades[k][1]:
                wins += 1
    return rts, wins


def replay_series_m7(series, p, fee, slip, starting_cash):
    if not starting_cash > 0:
        raise JsThrow("startingCashUsd must be > 0")
    book = {"cash": to_micro(starting_cash), "positions": {}, "fee": fee, "slip": slip}
    closes_all = [r["close"] for r in series]
    equity, trades, in_pos = [], [], False
    warmup = max(p["momentumLookback"], p["zWindow"], p["volWindow"]) + 2
    for i in range(warmup, len(series) - 1):
        action = evaluate_action_m7(closes_all[:i + 1], p)
        nxt = closes_all[i + 1]
        if action == "ENTER_LONG" and not in_pos:
            cash_usd = float(micro_str(book["cash"]))
            notional = float(math.floor(cash_usd * p["positionFraction"] * 100)) / 100
            if notional >= 10:
                _paper_fill_m7(book, "BUY", nxt, notional_usd=notional)
                in_pos = True
                trades.append(("BUY", nxt))
        elif action == "EXIT_LONG" and in_pos:
            pos = book["positions"]["ASSET"]
            if pos["qtyE9"] > 0:
                _paper_fill_m7(book, "SELL", nxt, qty=pos["qtyE9"])
                in_pos = False
                trades.append(("SELL", nxt))
        eq = _equity_str_m7(book, closes_all[i + 1])
        if eq is not None:
            equity.append(float(eq))
    final = _equity_str_m7(book, closes_all[-1])
    final_eq = float(final) if final is not None else None
    rts, wins = count_round_trips_m7(trades)
    mdd = None
    if equity:
        peak, mdd = float("-inf"), 0
        for e in equity:
            peak = max(peak, e)
            if peak > 0:
                mdd = max(mdd, (peak - e) / peak)
    out = {"finalEquityUsd": final_eq, "totalReturn": None if final_eq is None else final_eq / starting_cash - 1,
           "maxDrawdown": mdd, "nTrades": len(trades), "nRoundTrips": rts, "winRate": wins / rts if rts > 0 else None}
    if rts < 10:
        out["winRateNote"] = f"only {rts} round trips \u2014 win rate is statistically weak evidence"
    out["openAtEnd"] = in_pos
    return out


def walk_forward_m7(series, grid, fee, slip, is_fraction, starting_cash):
    split = math.floor(len(series) * is_fraction)
    ins = series[:split]
    outs = series[split - 60 if split - 60 >= 0 else 0:]
    results = []
    for params in grid:
        p = {k: _m7_param(params, k, k in ("momentumLookback", "zWindow", "volWindow")) for k in
             ("momentumLookback", "zWindow", "volWindow", "zEntry", "positionFraction")}
        if min(p["momentumLookback"], p["zWindow"], p["volWindow"]) < 0:
            raise _Unsupported("negative window parameter")
        results.append({"params": params, "inSample": replay_series_m7(ins, p, fee, slip, starting_cash),
                        "outOfSample": replay_series_m7(outs, p, fee, slip, starting_cash)})
    return {"splitIndex": split, "inSampleBars": len(ins), "outOfSampleBars": len(series) - split, "populationSize": len(grid),
            "cherryPickNote": "ALL configs reported (full population). Selecting the best cell after the fact is multiple testing \u2014 see METHODOLOGY.md.",
            "results": results}


def js_typeof(v):
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if v is True or v is False:
        return "boolean"
    if is_number(v):
        return "number"
    if isinstance(v, str):
        return "string"
    return "object"


def js_json_stringify(v):
    """JSON.stringify(v) (insertion order, no spaces); None for undefined."""
    if v is UNDEF:
        return None
    if v is None or v is True or v is False or is_number(v) or isinstance(v, str):
        if is_number(v) and not math.isfinite(float(v)):
            return "null"
        return canonicalize(v)
    if isinstance(v, list):
        return "[" + ",".join(js_json_stringify(x) or "null" for x in v) + "]"
    return "{" + ",".join(js_string_literal(k) + ":" + js_json_stringify(x) for k, x in js_entries(v) if x is not UNDEF) + "}"


def diff_path_m7(a, b, path="$"):
    """Twin of diffPathM7(): first divergence, for honest mismatch messages."""
    ta, tb = js_typeof(a), js_typeof(b)
    if ta == tb and ta in ("null", "undefined"):
        return None
    if ta == tb and ta in ("number", "string", "boolean") and a == b:
        return None
    if ta != tb:
        sa, sb = js_json_stringify(a), js_json_stringify(b)
        return f"{path} (recomputed {ta} {sa if sa is not None else js_to_string(a)} vs signed {tb} {sb if sb is not None else js_to_string(b)})"
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path}.length (recomputed {len(a)} vs signed {len(b)})"
        for i, (x, y) in enumerate(zip(a, b)):
            d = diff_path_m7(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    if ta == "object":
        keys = []
        for obj in (a, b):
            for k, x in js_entries(obj):
                if x is not UNDEF and k not in keys:
                    keys.append(k)
        for k in sorted(keys, key=utf16_key):
            d = diff_path_m7(get(a, int(k) if isinstance(a, list) else k), get(b, int(k) if isinstance(b, list) else k), f"{path}.{k}")
            if d:
                return d
        return None
    return f"{path} (recomputed {js_json_stringify(a)} vs signed {js_json_stringify(b)})"


def recompute_backtest(path, datasets_root):
    """Twin of recomputeBacktest(). None for non-backtest receipts, else a result dict."""
    try:
        st = _statement_of(path)
    except Exception:
        return None
    if get(st, "predicateType") != BACKTEST_PREDICATE_M7:
        return None
    summary = get(get(st, "predicate"), "summary")
    if not truthy(summary):
        return {"ok": False, "fails": ["backtest receipt missing predicate.summary"]}
    archive = get(summary, "datasetArchive")
    if not truthy(archive):
        return {"ok": True, "skip": "pre-generation-7 receipt (no datasetArchive) \u2014 numbers cannot be recomputed; signature/doctrine checks only"}
    pinned = js_to_string(coalesce(get(get(summary, "dataset"), "sha256"), ""))
    if not re.fullmatch(r"[0-9a-f]{64}", pinned):
        return {"ok": False, "fails": ["dataset.sha256 is not 64 lowercase hex chars"]}
    expect = f"data/datasets/{pinned}.json"
    if get(archive, "path") != expect:
        return {"ok": False, "fails": [f'datasetArchive.path "{js_to_string(get(archive, "path"))}" is not the canonical "{expect}" (anchored exact match required \u2014 no traversal, no aliases)']}
    try:
        with open(os.path.join(datasets_root, "data", "datasets", f"{pinned}.json"), "rb") as fh:
            data = fh.read()
    except OSError:
        return {"ok": False, "fails": [f"declared dataset archive MISSING at {expect} \u2014 a MEASURED claim whose inputs are gone does not re-verify (fail closed)"]}
    if sha256_hex(data) != pinned:
        return {"ok": False, "fails": [f"archived dataset bytes hash {sha256_hex(data)[:16]}\u2026 \u2260 pinned {pinned[:16]}\u2026 \u2014 dataset bytes TAMPERED or corrupted"]}
    try:
        series = json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"ok": False, "fails": ["archived dataset is not valid JSON"]}
    if not isinstance(series, list) or len(series) < 2 or not all(
            truthy(r) and _js_finite(get(r, "tMs")) and _js_finite(get(r, "close")) and get(r, "close") > 0 for r in series):
        return {"ok": False, "fails": ["archived dataset rows invalid \u2014 need [{tMs, close>0}, \u2026]"]}
    fails = []
    n = get(get(summary, "dataset"), "n")
    if not (is_number(n) and n == len(series)):
        fails.append(f"dataset.n {js_to_string(n)} \u2260 archived row count {len(series)}")
    method = coalesce(get(summary, "method"), {})
    replay = coalesce(get(method, "replay"), {})
    cm = coalesce(get(method, "costModel"), {})
    grid = get(method, "grid")
    if not isinstance(grid, list) or not grid:
        fails.append("method.grid missing/empty \u2014 cannot recompute")
    isf, cash = get(replay, "isFraction"), get(replay, "startingCashUsd")
    if not _js_finite(isf) or not (0 < isf < 1):
        fails.append("method.replay.isFraction missing/invalid \u2014 replay contract incomplete")
    if not _js_finite(cash) or not cash > 0:
        fails.append("method.replay.startingCashUsd missing/invalid \u2014 replay contract incomplete")
    if not _js_finite(get(cm, "feeBps")) or not _js_finite(get(cm, "slippageBps")):
        fails.append("method.costModel missing finite feeBps/slippageBps")
    version = get(replay, "version")
    if version is not UNDEF and not (is_number(version) and version in (7, 8)):
        fails.append("unsupported replay version")
    if fails:
        return {"ok": False, "fails": fails}
    if is_number(version) and version == 8:
        return {"ok": True, "not_assessed": "generation-8 replay is not implemented in the Python twin; run verify.mjs"}
    rows = [{"close": float(get(r, "close"))} for r in series]
    try:
        recomputed = walk_forward_m7(rows, grid, float(get(cm, "feeBps")), float(get(cm, "slippageBps")), float(isf), float(cash))
    except JsThrow as exc:
        return {"ok": False, "fails": [f"replay threw: {exc}"]}
    except _Unsupported as exc:
        return {"ok": True, "not_assessed": f"outside what the Python twin mirrors ({exc}); run verify.mjs"}
    signed = coalesce(get(summary, "walkForward"), None)
    if canonicalize(recomputed) != canonicalize(signed):
        where = diff_path_m7(recomputed, signed)
        return {"ok": False, "fails": [f"RECOMPUTE MISMATCH at {where} \u2014 the signed numbers do NOT re-derive from the archived dataset (a valid signature cannot rescue false numbers)"]}
    return {"ok": True, "recomputed": True, "cells": len(grid), "bars": len(series)}


# -------------------------------------------------------------------- refusals
REFUSALS_RE = re.compile(r"refusals_[0-9]+\.receipt\.json")


def _js_to_number(v):
    if v is None:
        return 0.0
    if v is UNDEF:
        return float("nan")
    if v is True or v is False:
        return 1.0 if v else 0.0
    if is_number(v):
        return float(v)
    s = js_to_string(v).strip()
    if s == "":
        return 0.0
    try:
        if s.lower().startswith(("0x", "0o", "0b")):
            return float(int(s, 0))
        if s in ("Infinity", "+Infinity", "-Infinity"):
            return float(s.replace("Infinity", "inf"))
        if re.fullmatch(r"[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?", s):
            return float(s)
    except ValueError:
        pass
    return float("nan")


def js_less(a, b):
    """The JavaScript `a < b` abstract relational comparison for JSON values."""
    pa = a if isinstance(a, str) else (js_to_string(a) if isinstance(a, (list, dict)) else a)
    pb = b if isinstance(b, str) else (js_to_string(b) if isinstance(b, (list, dict)) else b)
    if isinstance(pa, str) and isinstance(pb, str):
        return utf16_key(pa) < utf16_key(pb)
    x, y = _js_to_number(pa), _js_to_number(pb)
    return x < y  # NaN compares false, as in JS


def _js_stable_sort(values, cmp):
    import functools
    return sorted(values, key=functools.cmp_to_key(cmp))


def refusals_decision_mirror(name, st):
    """Twin of refusalsDecisionMirror()."""
    dec = get(get(st, "predicate"), "decision")
    if not truthy(get(get(dec, "asset"), "symbol")) or not truthy(get(dec, "proposedAction")) or not truthy(get(dec, "verdict")):
        return None
    blocked = get(dec, "blockedBy")
    conv = get(dec, "conviction")
    return {
        "file": name,
        "symbol": get(get(dec, "asset"), "symbol"),
        "verdict": get(dec, "verdict"),
        "proposedAction": get(dec, "proposedAction"),
        "conviction": conv if is_number(conv) else None,
        "blockedBy": js_sort(list(blocked)) if isinstance(blocked, list) else [],
    }


def refusals_census_mirror(decisions, excluded):
    """Twin of refusalsCensusMirror()."""
    ordered = _js_stable_sort(decisions, lambda a, b: -1 if js_less(a["symbol"], b["symbol"]) else (1 if js_less(b["symbol"], a["symbol"]) else 0))
    by_action, gate_counts, allowed, blocked = {}, {}, 0, 0
    for d in ordered:
        k = js_to_string(d["proposedAction"])
        by_action[k] = by_action.get(k, 0) + 1
        if d["verdict"] == "ALLOWED":
            allowed += 1
        else:
            blocked += 1
        for g in d["blockedBy"]:
            gk = js_to_string(g) if g is not UNDEF else "undefined"
            gate_counts[gk] = gate_counts.get(gk, 0) + 1
    by_gate = [{"gate": g, "count": n} for g, n in sorted(gate_counts.items(), key=lambda kv: utf16_key(kv[0]))]
    return {
        "inputs": {"signalFiles": sorted((d["file"] for d in ordered), key=utf16_key),
                   "excludedSignals": {"count": len(excluded), "files": sorted(excluded, key=utf16_key)}},
        "decisions": ordered,
        "totals": {"decisions": len(ordered), "allowed": allowed, "blocked": blocked, "byAction": by_action, "refusalsByGate": by_gate},
    }


def _summary_of(full):
    try:
        with open(full, "rb") as fh:
            env = json_loads(fh.read().decode("utf-8"))
        return coalesce(get(get(json_loads(base64.b64decode(get(env, "payload")).decode("utf-8")), "predicate"), "summary"), None)
    except Exception:
        return UNDEF


def _statement_of(full):
    with open(full, "rb") as fh:
        env = json_loads(fh.read().decode("utf-8"))
    return json_loads(base64.b64decode(get(env, "payload")).decode("utf-8"))


def verify_refusals(ledger_dir, pinned_der, out=print):
    """Twin of verifyRefusals(): replays every refusal census from DSSE-verified signal receipts."""
    try:
        dirs = sorted((e.name for e in _entries(ledger_dir) if e.is_dir(follow_symlinks=False)), key=utf16_key)
    except OSError as exc:
        out(f"REFUSALS FAIL: cannot read {ledger_dir}: {exc}")
        return False
    problems, recs = [], []
    for d in dirs:
        names = sorted((e.name for e in _entries(os.path.join(ledger_dir, d)) if e.is_file(follow_symlinks=False)), key=utf16_key)
        rfs = [n for n in names if REFUSALS_RE.fullmatch(n)]
        if len(rfs) > 1:
            problems.append(f"{d}: {len(rfs)} refusal records in one dir (ambiguous)")
        for rf in rfs:
            full = os.path.join(ledger_dir, d, rf)
            r = verify_file(full, pinned_der)
            if not r["ok"]:
                problems.append(f"{d}/{rf}: refusal record fails verification: {'; '.join(r['fails'])}")
            body = _summary_of(full)
            if not truthy(body) or get(body, "kind") != "szl-quant-refusals":
                problems.append(f"{d}/{rf}: unreadable refusal record body")
                continue
            if get(body, "runDir") != d:
                problems.append(f"{d}/{rf}: body.runDir {js_to_string(get(body, 'runDir'))} \u2260 actual dir {d}")
            recs.append({"dir": d, "file": rf, "body": body})
    if not recs:
        out("REFUSALS FAIL: no refusal records found under " + ledger_dir)
        return False
    for rec in recs:
        rdir = os.path.join(ledger_dir, rec["dir"])
        sig_names = sorted((e.name for e in _entries(rdir) if e.is_file(follow_symlinks=False)
                            and e.name.startswith("signal_") and e.name.endswith(".receipt.json")), key=utf16_key)
        decisions, excluded = [], []
        for n in sig_names:
            if not verify_file(os.path.join(rdir, n), pinned_der)["ok"]:
                excluded.append(n)
                continue
            try:
                st = _statement_of(os.path.join(rdir, n))
            except Exception:
                excluded.append(n)
                continue
            dec = refusals_decision_mirror(n, st)
            if dec is not None:
                decisions.append(dec)
        expect = refusals_census_mirror(decisions, excluded)
        body = rec["body"]
        if canonicalize(coalesce(get(body, "inputs"), None)) != canonicalize(expect["inputs"]):
            problems.append(f"{rec['dir']}: inputs do not match the verified signal receipts on disk")
        if canonicalize(coalesce(get(body, "decisions"), None)) != canonicalize(expect["decisions"]):
            problems.append(f"{rec['dir']}: decision census does not REPLAY from the signed receipts")
        if canonicalize(coalesce(get(body, "totals"), None)) != canonicalize(expect["totals"]):
            problems.append(f"{rec['dir']}: totals do not replay \u2014 refusal counts cannot be trusted")
    for p in problems:
        out(f"      REFUSALS FAIL: {p}")
    if not problems:
        h = recs[-1]["body"]
        totals = get(h, "totals")
        gates = _js_stable_sort(list(coalesce(get(totals, "refusalsByGate"), [])),
                                lambda a, b: (lambda x: 0 if x != x else (1 if x > 0 else (-1 if x < 0 else 0)))(_js_to_number(get(b, "count")) - _js_to_number(get(a, "count"))))
        gate_txt = " ".join(f"{js_to_string(get(x, 'gate'))}\u00d7{js_to_string(get(x, 'count'))}" for x in gates)
        out(f"REFUSALS OK  records={len(recs)}  latest {js_to_string(get(h, 'runDir'))}: BLOCKED {js_to_string(get(totals, 'blocked'))}/{js_to_string(get(totals, 'decisions'))}"
            + (f"  by gate: {gate_txt}" if gate_txt else "") + " [MEASURED]")
        out("      note: every count recomputed from DSSE-verified decision receipts alone \u2014 a refusal is a decision, not an absence")
        return True
    out("REFUSALS BROKEN")
    return False


# ------------------------------------------------------------------------ main
USAGE = ("usage: python verify/verify.py [--pubkey keys/engine_pubkey.json] "
         "(--dir receipts/ | --chain ledger/ | --book ledger/ | --refusals ledger/ | receipt.json ...)")


def main(argv=None, out=print):
    args = list(sys.argv[1:] if argv is None else argv)
    pinned, chain_dir, book_dir, refusals_dir, files, unsupported = None, None, None, None, [], []
    datasets_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    i = 0
    try:
        while i < len(args):
            a = args[i]
            if a == "--pubkey":
                i += 1
                pinned = load_pin(args[i])
            elif a == "--dir":
                i += 1
                d = args[i]
                for f in os.listdir(d):
                    full = os.path.join(d, f)
                    if f.endswith(".json") and os.path.isfile(full):
                        files.append(full)
            elif a == "--chain":
                i += 1
                chain_dir = args[i]
            elif a == "--book":
                i += 1
                book_dir = args[i]
            elif a == "--refusals":
                i += 1
                refusals_dir = args[i]
            elif a == "--datasets-root":
                i += 1
                datasets_root = args[i]
            elif a in ("--witness", "--rekor-pubkey", "--tsa-anchors", "--observer-pubkey"):
                unsupported.append(a)
                i += 1
            else:
                files.append(a)
            i += 1
    except IndexError:
        print(USAGE, file=sys.stderr)
        return 2
    except (OSError, ValueError, binascii.Error) as exc:
        print(f"ARG-ERROR {exc}", file=sys.stderr)
        return 2
    if unsupported:
        print(f"not implemented in the Python twin (use verify.mjs): {' '.join(unsupported)}", file=sys.stderr)
        return 2
    if not files and not chain_dir and not book_dir and not refusals_dir:
        print(USAGE, file=sys.stderr)
        return 2
    all_ok = True
    stats = {"recomputed": 0, "skipped": 0, "failed": 0, "not_assessed": 0}
    for f in sorted(files, key=utf16_key):
        r = verify_file(f, pinned)
        all_ok = all_ok and r["ok"]
        out(f"{'PASS' if r['ok'] else 'FAIL'}  {f}" + (f"  keyid={r['keyid']}" if r.get("keyid") else ""))
        for n in r.get("notes", []):
            out(f"      note: {n}")
        for x in r.get("fails", []):
            out(f"      FAIL: {x}")
        if r["ok"]:
            rr = recompute_backtest(f, datasets_root)
            if rr is None:
                continue
            if rr["ok"] and rr.get("recomputed"):
                stats["recomputed"] += 1
                out(f"      recompute: OK \u2014 {rr['cells']} grid cell(s) re-derived bit-exact from {rr['bars']} archived bars (MEASURED, recomputed)")
            elif rr["ok"] and rr.get("skip"):
                stats["skipped"] += 1
                out(f"      recompute: SKIP \u2014 {rr['skip']}")
            elif rr["ok"]:
                stats["not_assessed"] += 1
                out(f"      recompute: NOT ASSESSED \u2014 {rr['not_assessed']}")
            else:
                stats["failed"] += 1
                all_ok = False
                for x in rr["fails"]:
                    out(f"      RECOMPUTE FAIL: {x}")
    if files:
        out(f"\nAll {len(files)} receipt(s) verified." if all_ok else "\nVERIFICATION FAILED")
    if stats["recomputed"] + stats["skipped"] + stats["failed"] > 0:
        out(f"Recompute (generation 7): {stats['recomputed']} backtest receipt(s) re-derived bit-exact, {stats['skipped']} skipped (pre-gen7), {stats['failed']} FAILED.")
    if stats["not_assessed"]:
        out(f"Recompute: {stats['not_assessed']} backtest receipt(s) NOT ASSESSED by the Python twin (verify.mjs is authoritative for them).")
    if chain_dir:
        all_ok = verify_chain(chain_dir, pinned, out) and all_ok
    if book_dir:
        try:
            all_ok = verify_book(book_dir, pinned, out) and all_ok
        except Exception as exc:  # verify.mjs throws here and exits non-zero
            print(f"BOOK CRASH (verify.mjs throws here too): {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    if refusals_dir:
        all_ok = verify_refusals(refusals_dir, pinned, out) and all_ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
