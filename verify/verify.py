#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""verify.py: Python twin of verify/verify.mjs (receipt and chain checks).

Independent like verify.mjs: imports nothing from src/ or from the JS. It
reimplements canonical JSON (ECMAScript JSON.stringify semantics), DSSE PAE,
the doctrine checks and the hash-chain walk, and prints the same per-check
lines so both verifiers can be compared on the same inputs.

Usage:
    python verify/verify.py <receipt.json> [more.json ...]
    python verify/verify.py --dir receipts/
    python verify/verify.py --pubkey keys/engine_pubkey.json --dir DIR
    python verify/verify.py --pubkey keys/engine_pubkey.json --chain ledger/

Scope: --book, --refusals and --witness (and the generation-7 backtest
recompute) are NOT implemented here; verify.mjs stays authoritative for
them. A backtest receipt that verify.mjs would recompute is reported as
"recompute: NOT ASSESSED" instead of being silently treated as covered.

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


def needs_recompute(path):
    """True when verify.mjs would run its generation-7 backtest recompute on this file."""
    try:
        with open(path, "rb") as fh:
            env = json_loads(fh.read().decode("utf-8"))
        st = json_loads(base64.b64decode(get(env, "payload")).decode("utf-8"))
    except Exception:
        return False
    return get(st, "predicateType") == BACKTEST_PREDICATE_M7


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


# ------------------------------------------------------------------------ main
USAGE = ("usage: python verify/verify.py [--pubkey keys/engine_pubkey.json] "
         "(--dir receipts/ | --chain ledger/ | receipt.json ...)")


def main(argv=None, out=print):
    args = list(sys.argv[1:] if argv is None else argv)
    pinned, chain_dir, files, unsupported = None, None, [], []
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
            elif a in ("--book", "--refusals", "--witness", "--rekor-pubkey", "--tsa-anchors", "--observer-pubkey", "--datasets-root"):
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
    if not files and not chain_dir:
        print(USAGE, file=sys.stderr)
        return 2
    all_ok, not_assessed = True, 0
    for f in sorted(files, key=utf16_key):
        r = verify_file(f, pinned)
        all_ok = all_ok and r["ok"]
        out(f"{'PASS' if r['ok'] else 'FAIL'}  {f}" + (f"  keyid={r['keyid']}" if r.get("keyid") else ""))
        for n in r.get("notes", []):
            out(f"      note: {n}")
        for x in r.get("fails", []):
            out(f"      FAIL: {x}")
        if r["ok"] and needs_recompute(f):
            not_assessed += 1
            out("      recompute: NOT ASSESSED \u2014 Python twin covers receipt and chain checks only; run verify.mjs for generation-7 recompute")
    if files:
        out(f"\nAll {len(files)} receipt(s) verified." if all_ok else "\nVERIFICATION FAILED")
    if not_assessed:
        out(f"Recompute: {not_assessed} backtest receipt(s) NOT ASSESSED by the Python twin.")
    if chain_dir:
        all_ok = verify_chain(chain_dir, pinned, out) and all_ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
