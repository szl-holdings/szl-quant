# SPDX-License-Identifier: Apache-2.0
"""Parity tests: verify/verify.py against verify/verify.mjs (stdlib unittest).

Covers the receipt, chain, book and refusal checks.

Run from the repo root:
    python -m unittest discover -s test -p "test_verify_py.py" -v

Every parity test runs BOTH verifiers on the same generated receipts or
ledgers and requires identical verdicts and identical FAIL/note lines.
Canonical-JSON vectors run through the canonicalize() source extracted from
verify.mjs itself. Under GitHub Actions, node and `cryptography` are required,
so these tests cannot silently skip there.

test/fixtures/pyverify/<run dir>/ is a byte copy of one published run
directory from the ledger branch; its files are checked against the sha256
values sealed by that directory's own chain link.
"""
import base64
import hashlib
import importlib.util
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("szl_verify_py", REPO / "verify" / "verify.py")
vpy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpy)

NODE = shutil.which("node")
IN_CI = os.environ.get("GITHUB_ACTIONS") == "true"
VERIFY_MJS = REPO / "verify" / "verify.mjs"
FIXTURES = REPO / "test" / "fixtures" / "pyverify"
ENGINE_PIN = REPO / "keys" / "engine_pubkey.json"

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - CI requires it (see AvailabilityGuard)
    HAVE_CRYPTO = False


class AvailabilityGuard(unittest.TestCase):
    def test_parity_tests_cannot_skip_in_ci(self):
        if IN_CI:
            self.assertTrue(NODE, "node is required for verify.mjs parity in CI")
            self.assertTrue(HAVE_CRYPTO, "cryptography is required for signature tests in CI")


# ------------------------------------------------------------------ helpers
DOCTRINE = {
    "posture": {"mode": "ADVISORY_PAPER_ONLY", "provenTrust": False},
    "trustCeiling": 0.97,
    "lockedProvenFormulaIds": ["F1", "F4", "F7", "F11", "F12", "F18", "F19", "F22"],
    "lambdaStatus": "Conjecture 1 (open) - advisory only",
}


class Key:
    def __init__(self):
        self.priv = Ed25519PrivateKey.generate()
        self.spki = self.priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.keyid = hashlib.sha256(self.spki).hexdigest()[:16]

    def pin(self, path):
        Path(path).write_text(json.dumps({"kind": "szl-quant-engine-pubkey", "v": 1, "alg": "ed25519",
                                          "keyId": self.keyid,
                                          "publicKeySpkiBase64": base64.b64encode(self.spki).decode()}), encoding="utf-8")

    def envelope(self, payload, payload_type=vpy.PAYLOAD_TYPE, keyid=None, embed=True):
        sig = self.priv.sign(vpy.pae(payload_type, payload))
        env = {"payloadType": payload_type, "payload": base64.b64encode(payload).decode(),
               "signatures": [{"keyid": keyid or self.keyid, "sig": base64.b64encode(sig).decode()}]}
        if embed:
            env["publicKeySpkiBase64"] = base64.b64encode(self.spki).decode()
        return env


def statement(decision=None, summary=None, doctrine=DOCTRINE, digest="auto", predicate_type="https://szl.holdings/quant/signal/v1", extra=None):
    pred = {"_doctrine": doctrine}
    if decision is not None:
        pred["decision"] = decision
    if summary is not None:
        pred["summary"] = summary
    pred.update(extra or {})
    st = {"_type": vpy.IN_TOTO, "predicateType": predicate_type, "predicate": pred}
    dec = decision if decision is not None else summary
    if digest == "auto":
        digest = hashlib.sha256(vpy.canonicalize(dec).encode()).hexdigest() if dec is not None else None
    if digest is not None:
        st["subject"] = [{"name": "fixture", "digest": {"sha256": digest}}]
    return st


def payload_of(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_report(text):
    """{basename: (status, fails, notes)} plus the CHAIN lines, ignoring recompute lines."""
    files, chain, cur = {}, [], None
    for line in text.splitlines():
        if line.startswith(("PASS  ", "FAIL  ")):
            status, rest = line.split("  ", 1)
            name = os.path.basename(rest.split("  keyid=")[0])
            cur = files[name] = (status, [], [])
        elif line.startswith("      FAIL: ") and cur is not None:
            cur[1].append(line[len("      FAIL: "):])
        elif line.startswith("      note: ") and cur is not None:
            cur[2].append(line[len("      note: "):])
        elif "CHAIN" in line:
            chain.append(line.strip())
    return {k: (v[0], tuple(v[1]), tuple(v[2])) for k, v in files.items()}, chain


def run_node(args):
    p = subprocess.run([NODE, str(VERIFY_MJS), *args], capture_output=True, text=True, encoding="utf-8", cwd=REPO, timeout=120)
    return p.returncode, p.stdout


def run_py(args):
    lines = []
    code = vpy.main(list(args), out=lines.append)
    return code, "\n".join(lines)


def tmpdir(test):
    d = Path(tempfile.mkdtemp(prefix="pyverify-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


# ------------------------------------------------------ canonical JSON parity
def _node_canonicalize(texts):
    src = VERIFY_MJS.read_text(encoding="utf-8")
    start = src.index("function canonicalize(v) {")
    end = src.index("\n}\n", start) + 2
    script = src[start:end] + """
const chunks = []; process.stdin.on('data', (c) => chunks.push(c)); process.stdin.on('end', () => {
  const texts = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  process.stdout.write(JSON.stringify(texts.map((t) => { try { return canonicalize(JSON.parse(t)); } catch (e) { return 'ERROR'; } })));
});"""
    p = subprocess.run([NODE, "--input-type=module", "-e", script], input=json.dumps(texts), capture_output=True,
                       text=True, encoding="utf-8", timeout=120, check=True)
    return json.loads(p.stdout)


FIXED_VECTORS = [
    "0", "-0", "-0.0", "1.0", "1E5", "1e21", "1e20", "123456789012345678901234567890", "9007199254740993",
    "0.1", "0.30000000000000004", "1e-7", "0.000001", "2.5e-5", "5e-324", "1.7976931348623157e308", "-1.5e+300",
    "100", "1.50", "0.97", "1e400", "-1e400", "true", "false", "null",
    '"plain"', '"\\u0000\\u001f\\u007f\\u2028\\u2029"', '"\\ud800"', '"\\udfff x"', '"\\ud83d\\ude00"', '"quote\\" back\\\\ slash"',
    '{"b":1,"a":2,"10":3,"2":4,"\\u00e9":5,"Z":6,"\\ud83d\\ude00":7,"\\uff61":8}',
    '[1,[2,[3,{"x":[]}]],{}]', '{"a":{"c":1,"b":[{"z":0.5,"y":-0}]}}', '{"dup":1,"dup":2}',
]


def _fuzz_texts(n, seed=20261028):
    rng = random.Random(seed)

    def num():
        r = rng.random()
        if r < 0.3:
            while True:
                x = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]
                if x == x and abs(x) != float("inf"):
                    return repr(x).replace("inf", "1e400")
        if r < 0.5:
            return str(rng.randint(-10**25, 10**25))
        if r < 0.7:
            return "%de%d" % (rng.randint(-999, 999), rng.randint(-30, 30))
        return repr(round(rng.uniform(-1e6, 1e6), rng.randint(0, 12)))

    def string():
        out = []
        for _ in range(rng.randint(0, 6)):
            r = rng.random()
            if r < 0.4:
                out.append(chr(rng.randint(0x20, 0x7e)).replace("\\", "\\\\").replace('"', '\\"'))
            elif r < 0.6:
                out.append("\\u%04x" % rng.randint(0, 0x1f))
            elif r < 0.75:
                out.append("\\u%04x" % rng.randint(0xd800, 0xdfff))
            else:
                out.append(chr(rng.choice([0xe9, 0x3bb, 0x2014, 0x4e2d, 0x1f600, 0x10ffff])))
        return '"' + "".join(out) + '"'

    def value(depth):
        r = rng.random()
        if depth > 3 or r < 0.35:
            return num()
        if r < 0.55:
            return string()
        if r < 0.6:
            return rng.choice(["true", "false", "null"])
        if r < 0.8:
            return "[" + ",".join(value(depth + 1) for _ in range(rng.randint(0, 4))) + "]"
        return "{" + ",".join(string() + ":" + value(depth + 1) for _ in range(rng.randint(0, 5))) + "}"

    return [value(0) for _ in range(n)]


def _py_canonicalize(text):
    try:
        return vpy.canonicalize(vpy.json_loads(text))
    except ValueError:
        return "ERROR"


@unittest.skipUnless(NODE, "node is required for verify.mjs parity")
class CanonicalParityTests(unittest.TestCase):
    def test_fixed_vectors_match_verify_mjs(self):
        js = _node_canonicalize(FIXED_VECTORS)
        for text, want in zip(FIXED_VECTORS, js):
            self.assertEqual(_py_canonicalize(text), want, text)

    def test_fuzzed_documents_match_verify_mjs(self):
        texts = _fuzz_texts(600)
        js = _node_canonicalize(texts)
        mismatches = [(t, _py_canonicalize(t), j) for t, j in zip(texts, js) if _py_canonicalize(t) != j]
        self.assertEqual(mismatches[:3], [], f"{len(mismatches)} of {len(texts)} differ")


class CanonicalUnitTests(unittest.TestCase):
    """Node-independent anchors for the ECMAScript formatting rules."""

    def test_number_formatting(self):
        cases = {"0": "0", "-0.0": "0", "1.0": "1", "1E5": "100000", "1e21": "1e+21", "1e20": "100000000000000000000",
                 "0.000001": "0.000001", "1e-7": "1e-7", "5e-324": "5e-324", "123456789012345678901234567890": "1.2345678901234568e+29",
                 "9007199254740993": "9007199254740992", "-1.5e+300": "-1.5e+300", "0.30000000000000004": "0.30000000000000004"}
        for text, want in cases.items():
            self.assertEqual(vpy.canonicalize(vpy.json_loads(text)), want, text)

    def test_strings_keys_and_refusals(self):
        self.assertEqual(vpy.canonicalize(vpy.json_loads('"\\u0001\\ud800\\n"')), '"\\u0001\\ud800\\n"')
        self.assertEqual(vpy.canonicalize(vpy.json_loads('{"b":1,"\\uff61":2,"\\ud83d\\ude00":3,"a":[true,null]}')),
                         '{"a":[true,null],"b":1,"\U0001F600":3,"\uff61":2}')  # UTF-16 order: U+1F600 (D83D..) before U+FF61
        for text in ("1e400", "NaN", "Infinity"):
            with self.assertRaises(ValueError):
                vpy.canonicalize(vpy.json_loads(text))


# --------------------------------------------------------- receipt parity
def _decision(**kw):
    d = {"asset": "SOL", "verdict": "ALLOWED", "gates": [{"gate": "G1", "verdict": "ALLOWED"}],
         "signals": [{"conviction": 0.42}], "weird": {"\u00e9": 0.1, "10": 1e21, "2": [-0.0, 1.5]}}
    d.update(kw)
    return d


def receipt_cases(key, other):
    """name -> (envelope dict or raw bytes, expected Python status, expected fail substring or None)."""
    good = statement(_decision())
    dd = lambda **kw: dict(DOCTRINE, **kw)  # noqa: E731
    cases = {
        "valid": (key.envelope(payload_of(good)), "PASS", None),
        "summary_not_decision": (key.envelope(payload_of(statement(summary={"seq": 1, "gates": []}))), "PASS", None),
        "wrong_mode": (key.envelope(payload_of(statement(_decision(), doctrine=dd(posture={"mode": "LIVE", "provenTrust": False})))), "FAIL", "posture not ADVISORY_PAPER_ONLY"),
        "proven_trust_true": (key.envelope(payload_of(statement(_decision(), doctrine=dd(posture={"mode": "ADVISORY_PAPER_ONLY", "provenTrust": True})))), "FAIL", "provenTrust not locked false"),
        "proven_trust_missing": (key.envelope(payload_of(statement(_decision(), doctrine=dd(posture={"mode": "ADVISORY_PAPER_ONLY"})))), "FAIL", "provenTrust not locked false"),
        "ceiling_098": (key.envelope(payload_of(statement(_decision(), doctrine=dd(trustCeiling=0.98)))), "FAIL", "trustCeiling 0.98"),
        "ceiling_lower": (key.envelope(payload_of(statement(_decision(), doctrine=dd(trustCeiling=0.5)))), "FAIL", "trustCeiling 0.5"),
        "ceiling_string": (key.envelope(payload_of(statement(_decision(), doctrine=dd(trustCeiling="0.97")))), "FAIL", "trustCeiling 0.97"),
        "locked_missing": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lockedProvenFormulaIds=["F1", "F4"])))), "FAIL", "locked-proven set"),
        "locked_extra": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lockedProvenFormulaIds=DOCTRINE["lockedProvenFormulaIds"] + ["F2"])))), "FAIL", "locked-proven set"),
        "locked_numbers": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lockedProvenFormulaIds=[1, 4, 7, 11, 12, 18, 19, 22])))), "FAIL", "locked-proven set"),
        "locked_string": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lockedProvenFormulaIds="F1F4F7")))), "FAIL", "locked-proven set"),
        "lambda_missing": (key.envelope(payload_of(statement(_decision(), doctrine={k: v for k, v in DOCTRINE.items() if k != "lambdaStatus"}))), "FAIL", "Conjecture 1"),
        "lambda_theorem": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lambdaStatus="Conjecture 1 is now a THEOREM")))), "FAIL", "theorem"),
        "lambda_array": (key.envelope(payload_of(statement(_decision(), doctrine=dd(lambdaStatus=["Conjecture 1"])))), "PASS", None),
        "conviction_over": (key.envelope(payload_of(statement(_decision(signals=[{"conviction": 0.98}])))), "FAIL", "$.decision.signals.0.conviction = 0.98 exceeds"),
        "trust_int_over": (key.envelope(payload_of(statement(_decision(meta={"trust": 1})))), "FAIL", "$.decision.meta.trust = 1 exceeds"),
        "conviction_bool": (key.envelope(payload_of(statement(_decision(signals=[{"conviction": True}])))), "PASS", None),
        "digest_mismatch": (key.envelope(payload_of(statement(_decision(), digest="0" * 64))), "FAIL", "subject digest"),
        "digest_missing": (key.envelope(payload_of(statement(_decision(), digest=None))), "FAIL", "missing subject digest"),
        "no_decision_digest_unchecked": (key.envelope(payload_of(statement(None, digest="0" * 64))), "PASS", None),
        "gate_non_canon": (key.envelope(payload_of(statement(_decision(gates=[{"gate": "G9", "verdict": "MAYBE"}])))), "FAIL", "gate G9 has non-canon verdict MAYBE"),
        "gate_as_string": (key.envelope(payload_of(statement(_decision(gates="AB")))), "FAIL", "gate undefined has non-canon verdict undefined"),
        "blocked_no_gate": (key.envelope(payload_of(statement(_decision(verdict="BLOCKED")))), "FAIL", "no blocking gate"),
        "blocked_no_reason": (key.envelope(payload_of(statement(_decision(verdict="BLOCKED", gates=[{"gate": "G2", "verdict": "BLOCKED"}])))), "FAIL", "missing honest reason"),
        "blocked_ok": (key.envelope(payload_of(statement(_decision(verdict="BLOCKED", gates=[{"gate": "G2", "verdict": "BLOCKED", "reason": "stale data"}])))), "PASS", None),
        "falsy_payload_zero": (key.envelope(b"0"), "PASS", None),
        "falsy_payload_null": (key.envelope(b"null"), "PASS", None),
        "payload_not_json": (key.envelope(b"not json"), "FAIL", "payload not JSON"),
        "wrong_payload_type": (key.envelope(payload_of(good), payload_type="text/plain"), "FAIL", "payloadType text/plain"),
        "signed_by_other_key": (other.envelope(payload_of(good)), "FAIL", "no signature for keyid"),
        "other_key_claims_our_keyid": (other.envelope(payload_of(good), keyid=key.keyid), "FAIL", "ed25519 signature INVALID over PAE"),
        "statement_type_wrong": (key.envelope(payload_of(dict(good, _type="x"))), "FAIL", "statement _type x"),
        "backtest_predicate": (key.envelope(payload_of(statement(summary={"seq": 1}, predicate_type=vpy.BACKTEST_PREDICATE_M7))), "PASS", None),
    }
    return cases


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.key, self.other = Key(), Key()
        self.dir = tmpdir(self)
        self.pin = self.dir / "pin.json"
        self.key.pin(self.pin)
        self.rdir = self.dir / "receipts"
        self.rdir.mkdir()
        self.cases = receipt_cases(self.key, self.other)
        for name, (env, _, _) in self.cases.items():
            (self.rdir / f"{name}.json").write_text(json.dumps(env), encoding="utf-8")

    def test_each_case_has_the_expected_python_verdict(self):
        pinned = vpy.load_pin(str(self.pin))
        for name, (_, status, needle) in self.cases.items():
            r = vpy.verify_file(str(self.rdir / f"{name}.json"), pinned)
            self.assertEqual("PASS" if r["ok"] else "FAIL", status, (name, r["fails"]))
            if needle:
                self.assertTrue(any(needle in f for f in r["fails"]), (name, r["fails"]))

    def test_backtest_receipt_is_reported_not_assessed(self):
        code, out = run_py(["--pubkey", str(self.pin), str(self.rdir / "backtest_predicate.json")])
        self.assertEqual(code, 0)
        self.assertIn("recompute: NOT ASSESSED", out)

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_identical_report_to_verify_mjs_pinned_and_unpinned(self):
        for args in (["--pubkey", str(self.pin), "--dir", str(self.rdir)], ["--dir", str(self.rdir)]):
            jcode, jout = run_node(args)
            pcode, pout = run_py(args)
            self.assertEqual(parse_report(pout)[0], parse_report(jout)[0], args)
            self.assertEqual(pcode, jcode, args)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class StrictnessDifferenceTests(unittest.TestCase):
    """Documented reject-only differences: Python refuses what JS leniently accepts."""

    def test_non_canonical_base64_payload(self):
        key = Key()
        d = tmpdir(self)
        env = key.envelope(payload_of(statement(_decision())))
        env["payload"] = env["payload"][:8] + "\n" + env["payload"][8:]
        f = d / "r.json"
        f.write_text(json.dumps(env), encoding="utf-8")
        self.assertIn("payload not base64", vpy.verify_file(str(f), key.spki)["fails"])
        if NODE:
            key.pin(d / "pin.json")
            code, out = run_node(["--pubkey", str(d / "pin.json"), str(f)])
            self.assertEqual(code, 0, out)


# ----------------------------------------------------------- chain parity
def build_ledger(root, key, link_plan=None, seqs=None):
    """4 run dirs, 2 receipts each; links seal dirs per link_plan [(link_dir, [covered dirs])]."""
    dirs = ["20260101T000000Z_run1", "20260102T000000Z_run2", "20260103T000000Z_run3", "20260104T000000Z_run4"]
    for i, d in enumerate(dirs):
        (root / d).mkdir(parents=True)
        for j in range(2):
            (root / d / f"signal_{i}_{j}.receipt.json").write_text(json.dumps({"i": i, "j": j}), encoding="utf-8")
    plan = link_plan or [(dirs[0], [dirs[0]]), (dirs[1], [dirs[1]]), (dirs[3], [dirs[2], dirs[3]])]
    prev = None
    for idx, (link_dir, covered) in enumerate(plan):
        seq = seqs[idx] if seqs else idx + 1
        covers = [{"dir": c, "files": [{"name": n, "sha256": hashlib.sha256((root / c / n).read_bytes()).hexdigest()}
                                       for n in sorted(os.listdir(root / c)) if not vpy.CHAIN_RE.fullmatch(n)]} for c in covered]
        body = {"kind": "szl-quant-chain", "v": 1, "seq": seq, "prev": prev, "covers": covers}
        name = f"chain_{seq:04d}.receipt.json"
        raw = json.dumps(key.envelope(payload_of(statement(summary=body, predicate_type="https://szl.holdings/quant/chain/v1")))).encode()
        (root / link_dir / name).write_bytes(raw)
        prev = {"file": name, "runDir": link_dir, "sha256": hashlib.sha256(raw).hexdigest()}
    return dirs


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class ChainTests(unittest.TestCase):
    def setUp(self):
        self.key = Key()
        self.base = tmpdir(self)
        self.pin = self.base / "pin.json"
        self.key.pin(self.pin)

    def ledger(self, plan=None, seqs=None):
        root = self.base / f"ledger{len(os.listdir(self.base))}"
        dirs = build_ledger(root, self.key, plan, seqs)
        return root, dirs

    def mutations(self):
        def rewrite(root, dirs):
            p = root / dirs[1] / "signal_1_0.receipt.json"
            p.write_bytes(p.read_bytes() + b" ")
        def delete_file(root, dirs):
            (root / dirs[2] / "signal_2_1.receipt.json").unlink()
        def inject(root, dirs):
            (root / dirs[0] / "injected.json").write_text("{}", encoding="utf-8")
        def delete_dir(root, dirs):
            shutil.rmtree(root / dirs[2])
        def add_dir(root, dirs):
            (root / "20260105T000000Z_run5").mkdir()
        def forge_sig(root, dirs):
            p = root / dirs[1] / "chain_0002.receipt.json"
            env = json.loads(p.read_text(encoding="utf-8"))
            sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
            sig[3] ^= 1
            env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
            p.write_text(json.dumps(env), encoding="utf-8")
        def delete_link(root, dirs):
            (root / dirs[1] / "chain_0002.receipt.json").unlink()
        def two_links_one_dir(root, dirs):
            shutil.copy(root / dirs[1] / "chain_0002.receipt.json", root / dirs[1] / "chain_0009.receipt.json")
        return {"clean": None, "rewrite": rewrite, "delete_file": delete_file, "inject": inject, "delete_dir": delete_dir,
                "add_dir": add_dir, "forge_sig": forge_sig, "delete_link": delete_link, "two_links_one_dir": two_links_one_dir}

    def test_python_chain_verdicts(self):
        expect = {"clean": True, "rewrite": False, "delete_file": False, "inject": False, "delete_dir": False,
                  "add_dir": False, "forge_sig": False, "delete_link": False, "two_links_one_dir": False}
        for name, mutate in self.mutations().items():
            root, dirs = self.ledger()
            if mutate:
                mutate(root, dirs)
            lines = []
            self.assertEqual(vpy.verify_chain(str(root), self.key.spki, out=lines.append), expect[name], (name, lines))

    def test_seq_gap_with_intact_prev_pointers_is_refused(self):
        root, _ = self.ledger(seqs=[1, 2, 4])
        lines = []
        self.assertFalse(vpy.verify_chain(str(root), self.key.spki, out=lines.append))
        self.assertTrue(any("seq not contiguous: expected 3, found 4" in l for l in lines), lines)
        self.assertFalse(any("prev pointer mismatch" in l for l in lines), lines)

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_seq_gap_report_matches_verify_mjs(self):
        root, _ = self.ledger(seqs=[1, 2, 4])
        jcode, jout = run_node(["--pubkey", str(self.pin), "--chain", str(root)])
        pcode, pout = run_py(["--pubkey", str(self.pin), "--chain", str(root)])
        self.assertEqual((parse_report(pout)[1], pcode), (parse_report(jout)[1], jcode))

    def test_double_seal_is_refused(self):
        root, dirs = self.ledger([("20260101T000000Z_run1", ["20260101T000000Z_run1"]), ("20260102T000000Z_run2", ["20260102T000000Z_run2", "20260101T000000Z_run1"]),
                                  ("20260104T000000Z_run4", ["20260103T000000Z_run3", "20260104T000000Z_run4"])])
        lines = []
        self.assertFalse(vpy.verify_chain(str(root), self.key.spki, out=lines.append))
        self.assertTrue(any("sealed twice" in l for l in lines), lines)

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_identical_chain_report_to_verify_mjs(self):
        for name, mutate in self.mutations().items():
            root, dirs = self.ledger()
            if mutate:
                mutate(root, dirs)
            jcode, jout = run_node(["--pubkey", str(self.pin), "--chain", str(root)])
            pcode, pout = run_py(["--pubkey", str(self.pin), "--chain", str(root)])
            self.assertEqual(parse_report(pout)[1], parse_report(jout)[1], name)
            self.assertEqual(pcode, jcode, name)


# --------------------------------------------------------- real fixtures
@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class PublishedRunDirTests(unittest.TestCase):
    def setUp(self):
        dirs = [p for p in FIXTURES.iterdir() if p.is_dir()]
        self.assertEqual(len(dirs), 1)
        self.run_dir = dirs[0]

    def test_fixture_bytes_match_their_own_sealed_chain_link(self):
        links = [p for p in self.run_dir.iterdir() if vpy.CHAIN_RE.fullmatch(p.name)]
        self.assertEqual(len(links), 1)
        env = json.loads(links[0].read_text(encoding="utf-8"))
        body = json.loads(base64.b64decode(env["payload"]))["predicate"]["summary"]
        cover = [c for c in body["covers"] if c["dir"] == self.run_dir.name][0]
        on_disk = sorted(p.name for p in self.run_dir.iterdir() if not vpy.CHAIN_RE.fullmatch(p.name))
        self.assertEqual(sorted(f["name"] for f in cover["files"]), on_disk)
        for f in cover["files"]:
            self.assertEqual(hashlib.sha256((self.run_dir / f["name"]).read_bytes()).hexdigest(), f["sha256"], f["name"])

    def test_every_published_receipt_verifies_under_the_repository_pin(self):
        pinned = vpy.load_pin(str(ENGINE_PIN))
        for p in sorted(self.run_dir.iterdir()):
            r = vpy.verify_file(str(p), pinned)
            self.assertTrue(r["ok"], (p.name, r["fails"]))

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_identical_report_to_verify_mjs_on_published_receipts(self):
        args = ["--pubkey", str(ENGINE_PIN), "--dir", str(self.run_dir)]
        jcode, jout = run_node(args)
        pcode, pout = run_py(args)
        self.assertEqual(parse_report(pout)[0], parse_report(jout)[0])
        self.assertEqual((pcode, jcode), (0, 0))


# --------------------------------------------------------- refusals parity
def signal_decision(symbol, action, verdict, conviction=0.4, blocked=None):
    d = {"asset": {"symbol": symbol}, "proposedAction": action, "verdict": verdict, "conviction": conviction,
         "gates": [{"gate": g, "verdict": "BLOCKED", "reason": "fixture"} for g in (blocked or [])] or [{"gate": "G0", "verdict": "ALLOWED"}]}
    if blocked is not None:
        d["blockedBy"] = blocked
    return d


def build_refusals_ledger(root, key, run="20260201T000000Z_run1", signals=None, body_edit=None, kind="szl-quant-refusals"):
    rdir = root / run
    rdir.mkdir(parents=True)
    signals = signals or [("SOL", "BUY", "ALLOWED", 0.4, []), ("JUP", "BUY", "BLOCKED", 0.2, ["liquidity", "G10"]),
                          ("Bonk", "SELL", "BLOCKED", 0.1, ["G2", "liquidity"]), ("\u00e9t\u00e9", "HOLD", "ALLOWED", 0.3, None)]
    for sym, action, verdict, conv, blocked in signals:
        st = statement(signal_decision(sym, action, verdict, conv, blocked))
        (rdir / f"signal_{sym}_1.receipt.json").write_text(json.dumps(key.envelope(payload_of(st))), encoding="utf-8")
    decisions = []
    for n in sorted((p.name for p in rdir.iterdir()), key=vpy.utf16_key):
        dec = vpy.refusals_decision_mirror(n, vpy._statement_of(str(rdir / n)))
        if dec:
            decisions.append(dec)
    census = vpy.refusals_census_mirror(decisions, [])
    body = dict(census, kind=kind, runDir=run, v=1)
    if body_edit:
        body_edit(body)
    st = statement(summary=body, predicate_type="https://szl.holdings/quant/refusals/v1")
    (rdir / "refusals_1.receipt.json").write_text(json.dumps(key.envelope(payload_of(st))), encoding="utf-8")
    return rdir


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class RefusalsTests(unittest.TestCase):
    def setUp(self):
        self.key = Key()
        self.base = tmpdir(self)
        self.pin = self.base / "pin.json"
        self.key.pin(self.pin)

    def ledger(self, **kw):
        root = self.base / f"r{len(os.listdir(self.base))}"
        rdir = build_refusals_ledger(root, self.key, **kw)
        return root, rdir

    def test_hand_checked_census(self):
        root, rdir = self.ledger()
        body = json.loads(base64.b64decode(json.loads((rdir / "refusals_1.receipt.json").read_text())["payload"]))["predicate"]["summary"]
        self.assertEqual(body["totals"]["decisions"], 4)
        self.assertEqual((body["totals"]["allowed"], body["totals"]["blocked"]), (2, 2))
        self.assertEqual(body["totals"]["byAction"], {"BUY": 2, "SELL": 1, "HOLD": 1})
        self.assertEqual(body["totals"]["refusalsByGate"], [{"gate": "G10", "count": 1}, {"gate": "G2", "count": 1}, {"gate": "liquidity", "count": 2}])
        self.assertEqual([d["symbol"] for d in body["decisions"]], ["Bonk", "JUP", "SOL", "\u00e9t\u00e9"])
        self.assertEqual(body["decisions"][1]["blockedBy"], ["G10", "liquidity"])
        lines = []
        self.assertTrue(vpy.verify_refusals(str(root), self.key.spki, out=lines.append), lines)
        self.assertIn("BLOCKED 2/4  by gate: liquidity\u00d72 G10\u00d71 G2\u00d71", lines[0])

    def mutations(self):
        def tamper_signal(root, rdir):
            p = rdir / "signal_SOL_1.receipt.json"
            env = json.loads(p.read_text())
            sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
            sig[0] ^= 1
            env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
            p.write_text(json.dumps(env))
        def drop_signal(root, rdir):
            (rdir / "signal_JUP_1.receipt.json").unlink()
        def add_signal(root, rdir):
            st = statement(signal_decision("PYTH", "BUY", "BLOCKED", 0.2, ["liquidity"]))
            (rdir / "signal_PYTH_1.receipt.json").write_text(json.dumps(self.key.envelope(payload_of(st))))
        def second_record(root, rdir):
            shutil.copy(rdir / "refusals_1.receipt.json", rdir / "refusals_2.receipt.json")
        return {
            "clean": ({}, None),
            "deferred_verdict": ({"signals": [("SOL", "BUY", "ALLOWED", 0.4, []), ("PYTH", "BUY", "DEFERRED", 0.2, None)]}, None),
            "totals_lie": ({"body_edit": lambda b: b["totals"].__setitem__("blocked", 1)}, None),
            "decision_dropped": ({"body_edit": lambda b: b["decisions"].pop()}, None),
            "inputs_lie": ({"body_edit": lambda b: b["inputs"]["signalFiles"].pop()}, None),
            "wrong_rundir": ({"body_edit": lambda b: b.__setitem__("runDir", "other")}, None),
            "wrong_kind": ({"kind": "szl-quant-other"}, None),
            "tampered_signal": ({}, tamper_signal),
            "dropped_signal": ({}, drop_signal),
            "added_signal": ({}, add_signal),
            "two_records": ({}, second_record),
        }

    def test_python_refusal_verdicts(self):
        for name, (kw, mutate) in self.mutations().items():
            root, rdir = self.ledger(**kw)
            if mutate:
                mutate(root, rdir)
            lines = []
            self.assertEqual(vpy.verify_refusals(str(root), self.key.spki, out=lines.append), name in ("clean", "deferred_verdict"), (name, lines))

    def test_any_verdict_other_than_allowed_counts_as_blocked(self):
        sigs = [("SOL", "BUY", "ALLOWED", 0.4, []), ("PYTH", "BUY", "DEFERRED", 0.2, None)]
        root, rdir = self.ledger(signals=sigs)
        body = json.loads(base64.b64decode(json.loads((rdir / "refusals_1.receipt.json").read_text())["payload"]))["predicate"]["summary"]
        self.assertEqual((body["totals"]["allowed"], body["totals"]["blocked"]), (1, 1))
        lines = []
        self.assertTrue(vpy.verify_refusals(str(root), self.key.spki, out=lines.append), lines)
        self.assertIn("BLOCKED 1/2", lines[0])

    def test_no_records_is_a_failure(self):
        root = self.base / "empty"
        (root / "20260201T000000Z_run1").mkdir(parents=True)
        lines = []
        self.assertFalse(vpy.verify_refusals(str(root), self.key.spki, out=lines.append))
        self.assertIn("no refusal records found", lines[0])

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_identical_refusals_report_to_verify_mjs(self):
        for name, (kw, mutate) in self.mutations().items():
            root, rdir = self.ledger(**kw)
            if mutate:
                mutate(root, rdir)
            jcode, jout = run_node(["--pubkey", str(self.pin), "--refusals", str(root)])
            pcode, pout = run_py(["--pubkey", str(self.pin), "--refusals", str(root)])
            jl = [l.strip() for l in jout.splitlines() if "REFUSALS" in l]
            pl = [l.strip() for l in pout.splitlines() if "REFUSALS" in l]
            self.assertEqual((pl, pcode), (jl, jcode), name)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class PublishedRefusalsTests(unittest.TestCase):
    def test_published_run_dir_refusal_census_replays(self):
        lines = []
        self.assertTrue(vpy.verify_refusals(str(FIXTURES), vpy.load_pin(str(ENGINE_PIN)), out=lines.append), lines)
        self.assertTrue(lines[0].startswith("REFUSALS OK  records=1  latest 20260716T175421Z_run10"), lines)

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_published_refusals_report_matches_verify_mjs(self):
        args = ["--pubkey", str(ENGINE_PIN), "--refusals", str(FIXTURES)]
        jcode, jout = run_node(args)
        pcode, pout = run_py(args)
        self.assertEqual(([l.strip() for l in pout.splitlines() if "REFUSALS" in l], pcode),
                         ([l.strip() for l in jout.splitlines() if "REFUSALS" in l], jcode))


# ------------------------------------------------------------- book parity
BOOK_CONFIG = {"costModel": {"feeBps": 10, "slippageBps": 10}, "entryFractionBps": 1000, "startingCashUsd": 10000}


def book_signal(symbol, action, verdict, price, at="2026-02-01T00:00:00.000Z"):
    dec = {"asset": {"symbol": symbol}, "proposedAction": action, "verdict": verdict,
           "snapshot": {"priceUsd": price, "observedAtIso": at},
           "gates": [{"gate": "G1", "verdict": "BLOCKED", "reason": "fixture"}] if verdict == "BLOCKED" else [{"gate": "G1", "verdict": "ALLOWED"}]}
    return statement(dec)


def build_book_ledger(root, key, runs, config=BOOK_CONFIG, edits=None, pre=0, names=None, tamper=()):
    """runs: [(signals, booked)] where signals = [(symbol, action, verdict, price)].

    Book bodies are produced by the twin's own replay; the parity tests then
    require verify.mjs to accept and reject exactly the same ledgers, and the
    hand-checked test pins the arithmetic independently of either verifier.
    """
    edits = edits or {}
    names = names or [f"202602{i + 1:02d}T000000Z_run{i + 1}" for i in range(pre + len(runs))]
    for n in names[:pre]:
        (root / n).mkdir(parents=True)
        (root / n / "session_1.receipt.json").write_text("{}", encoding="utf-8")
    prev_link, prev_state, seq, last_booked = None, None, 0, None
    for idx, (signals, booked) in enumerate(runs):
        d = names[pre + idx]
        (root / d).mkdir(parents=True)
        for sym, action, verdict, price, *suffix in signals:
            env = key.envelope(payload_of(book_signal(sym, action, verdict, price)))
            fname = f"signal_{sym}_{suffix[0] if suffix else 1}.receipt.json"
            if (idx, fname) in tamper:
                sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
                sig[1] ^= 1
                env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
            (root / d / fname).write_text(json.dumps(env), encoding="utf-8")
        if not booked:
            continue
        seq += 1
        decisions, excluded = [], []
        for n in sorted((p.name for p in (root / d).iterdir() if p.name.startswith("signal_")), key=vpy.utf16_key):
            if not vpy.verify_file(str(root / d / n), key.spki)["ok"]:
                excluded.append(n)
                continue
            dec = vpy.book_decision_mirror(n, vpy._statement_of(str(root / d / n)))
            if dec:
                decisions.append(dec)
        if seq == 1:
            start = {"cashMicro": vpy.to_micro(config["startingCashUsd"]), "positions": {}}
        else:
            start = {"cashMicro": int(prev_state["cashMicro"]),
                     "positions": {a: {"qtyE9": int(p["qtyE9"]), "costMicro": int(p["costMicro"])} for a, p in prev_state["positions"].items()}}
        gen = f"2026-02-{pre + idx + 1:02d}T00:05:00.000Z"
        rep = vpy.replay_transition(start, config, decisions, gen)
        body = {"kind": "szl-quant-book", "v": 1, "seq": seq, "prev": prev_link, "runDir": d, "config": config, "generatedAtIso": gen,
                "inputs": {"signalFiles": sorted((x["file"] for x in rep["sortedDecisions"]), key=vpy.utf16_key),
                           "decisions": [{k: x[k] for k in ("file", "symbol", "proposedAction", "verdict", "priceUsd", "observedAtIso")} for x in rep["sortedDecisions"]],
                           "excludedSignals": {"count": len(excluded), "files": excluded}},
                "fills": rep["fills"], "noActions": rep["noActions"], "state": rep["state"], "mark": rep["mark"]}
        if seq == 1:
            body["preBookRunDirs"] = [n for n in sorted(names) if n < d]
        else:
            body["skippedRunDirs"] = [n for n in sorted(names) if last_booked < n < d]
        body = json.loads(json.dumps(body))  # edits must not leak into the generator's own state
        if seq in edits:
            edits[seq](body)
        name = f"book_{seq}.receipt.json"
        raw = json.dumps(key.envelope(payload_of(statement(summary=body, predicate_type="https://szl.holdings/quant/book/v1")))).encode()
        (root / d / name).write_bytes(raw)
        prev_link = {"file": name, "runDir": d, "sha256": hashlib.sha256(raw).hexdigest()}
        prev_state, last_booked = rep["state"], d
    return names


TRADE_RUNS = [([("SOL", "ENTER_LONG", "ALLOWED", 100), ("JUP", "HOLD", "ALLOWED", 1.5), ("Bonk", "ENTER_LONG", "BLOCKED", 0.00002)], True),
              ([("SOL", "EXIT_LONG", "ALLOWED", 110), ("JUP", "EXIT_LONG", "ALLOWED", 1.5)], True)]


def _summary(path):
    return json.loads(base64.b64decode(json.loads(Path(path).read_text(encoding="utf-8"))["payload"]))["predicate"]["summary"]


class JsNumberPrimitiveTests(unittest.TestCase):
    """Node-independent anchors: ECMAScript toFixed ties and BigInt truncation."""

    def test_to_fixed_matches_ecmascript_on_known_values(self):
        cases = [((0.25, 1), "0.3"), ((2.5, 0), "3"), ((0.0078125, 6), "0.007813"), ((-0.0078125, 6), "-0.007813"),
                 ((1.005, 2), "1.00"), ((-1e-7, 6), "-0.000000"), ((-0.0, 2), "0.00"), ((1e21, 2), "1e+21"), ((100.2, 10), "100.2000000000")]
        for (x, f), want in cases:
            self.assertEqual(vpy.js_to_fixed(x, f), want, (x, f))

    def test_bigint_division_truncates_toward_zero(self):
        self.assertEqual([vpy.tdiv(7, 2), vpy.tdiv(-7, 2), vpy.tdiv(7, -2), vpy.tdiv(-7, -2)], [3, -3, -3, 3])
        with self.assertRaises(vpy.JsThrow):
            vpy.tdiv(1, 0)

    def test_to_micro_and_bigint_errors(self):
        self.assertEqual((vpy.to_micro(0.0078125), vpy.to_micro(-2.5), vpy.to_micro(10000)), (7813, -2500000, 10_000_000_000))
        for bad in ("5", True, None, float("inf")):
            with self.assertRaises(vpy.JsThrow):
                vpy.to_micro(bad)
        with self.assertRaisesRegex(vpy.JsThrow, "The number 25.5 cannot be converted to a BigInt because it is not an integer"):
            vpy.js_bigint(25.5)
        self.assertEqual((vpy.js_bigint(" 12 "), vpy.js_bigint(""), vpy.js_bigint("0x10"), vpy.js_bigint("-5")), (12, 0, 16, -5))


@unittest.skipUnless(NODE, "node is required for verify.mjs parity")
class ToFixedParityTests(unittest.TestCase):
    def test_fuzzed_to_fixed_matches_node(self):
        rng = random.Random(7)
        vals = [k / 2 ** m for k in range(-40, 41) for m in range(0, 12)]
        vals += [struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0] for _ in range(400)]
        vals += [rng.uniform(-1e6, 1e6) for _ in range(400)] + [0.1, 0.7, 1.005, 2.675, 1e20, 9.5e20, -0.0]
        vals = [v for v in vals if v == v and abs(v) != float("inf")]
        cases = [(v, f) for v in vals for f in (0, 1, 2, 6, 10)]
        script = "const c=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.map(([b,f])=>{const v=new Float64Array(new Uint8Array(Buffer.from(b,'hex')).buffer)[0];return v.toFixed(f);})))"
        payload = json.dumps([[struct.pack("<d", v).hex(), f] for v, f in cases])
        p = subprocess.run([NODE, "-e", script], input=payload, capture_output=True, text=True, timeout=120, check=True)
        js = json.loads(p.stdout)
        bad = [(v, f, vpy.js_to_fixed(v, f), j) for (v, f), j in zip(cases, js) if vpy.js_to_fixed(v, f) != j]
        self.assertEqual(bad[:3], [], f"{len(bad)} of {len(cases)} differ")


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class BookTests(unittest.TestCase):
    def setUp(self):
        self.key = Key()
        self.base = tmpdir(self)
        self.pin = self.base / "pin.json"
        self.key.pin(self.pin)

    def ledger(self, runs=TRADE_RUNS, **kw):
        root = self.base / f"b{len(os.listdir(self.base))}"
        names = build_book_ledger(root, self.key, runs, **kw)
        return root, names

    def test_hand_checked_round_trip(self):
        """10,000 USD, 10% entry, 20 bps cost: buy SOL at 100, sell at 110 (numbers worked by hand)."""
        root, names = self.ledger()
        b1, b2 = _summary(root / names[0] / "book_1.receipt.json"), _summary(root / names[1] / "book_2.receipt.json")
        f = b1["fills"][0]
        self.assertEqual((f["side"], f["notionalUsd"], f["effectivePrice"], f["qtyE9"], f["modeledCostUsd"]),
                         ("BUY", "1000.000000", "100.2000000000", "9980039920", "1.996008"))
        self.assertEqual(b1["state"], {"cashMicro": "9000000000", "positions": {"SOL": {"qtyE9": "9980039920", "costMicro": "1000000000"}}})
        self.assertEqual((b1["mark"]["equityUsd"], b1["mark"]["positions"][0]["valueUsd"]), ("9998.003992", "998.003992"))
        self.assertEqual([x["why"] for x in b1["noActions"]], ["decision BLOCKED \u2014 fail closed, the gates hold the book", "HOLD \u2014 no book action"])
        s = b2["fills"][0]
        self.assertEqual((s["side"], s["notionalUsd"], s["effectivePrice"], s["modeledCostUsd"]), ("SELL", "1095.608782", "109.7800000000", "2.195609"))
        self.assertEqual((b2["state"], b2["mark"]["equityUsd"]), ({"cashMicro": "10095608782", "positions": {}}, "10095.608782"))
        self.assertEqual(b2["noActions"], [{"asset": "JUP", "action": "NONE", "why": "no open position to exit"}])
        lines = []
        self.assertTrue(vpy.verify_book(str(root), self.key.spki, out=lines.append), lines)
        self.assertEqual(lines[0], "BOOK OK  links=2  head=seq 2  equity=$10095.608782 [MODELED]  open=0  cash=$10095.608782")

    def test_tie_price_uses_ecmascript_rounding(self):
        root, names = self.ledger(runs=[([("PYTH", "ENTER_LONG", "ALLOWED", 0.0078125)], True)])
        f = _summary(root / names[0] / "book_1.receipt.json")["fills"][0]
        self.assertEqual(f["qtyE9"], str(1_000_000_000 * 1_000_000_000 // vpy.to_micro(0.0078125 * 1.002)))
        self.assertEqual(vpy.to_micro(0.0078125), 7813)  # Python's own round-half-even would give 7812
        self.assertEqual(f["modeledCostUsd"], vpy.micro_str(((1_000_000_000 * 1_000_000_000 // 7813) - int(f["qtyE9"])) * 7813 // 1_000_000_000))

    def test_hand_checked_fail_closed_branches(self):
        sc = self.scenarios()
        root, names = self.ledger(**sc["unpriced_open_position"][0])
        b2 = _summary(root / names[1] / "book_2.receipt.json")
        self.assertEqual(b2["fills"], [])
        self.assertIn({"asset": "JUP", "action": "NONE", "why": "an open position is unpriced \u2014 equity not computable, no new entries (fail closed)"}, b2["noActions"])
        self.assertEqual((b2["mark"]["equityUsd"], b2["mark"]["equityNote"]), (None, "1 position(s) unpriced \u2014 equity not computable (honest empty)"))
        self.assertEqual(b2["mark"]["positions"], [{"asset": "SOL", "qtyE9": "9980039920", "value": {"label": "UNAVAILABLE", "note": "no observed price at mark time"}}])
        root, names = self.ledger(**sc["insufficient_cash"][0])
        b1 = _summary(root / names[0] / "book_1.receipt.json")
        self.assertEqual([f["asset"] for f in b1["fills"]], ["A1", "B2"])
        skips = [x for x in b1["noActions"] if x["action"] == "SKIPPED_INSUFFICIENT_CASH"]
        self.assertEqual(len(skips), 10)
        self.assertTrue(skips[0]["why"].startswith("entry needs ") and skips[0]["why"].endswith(" \u2014 no leverage, honest skip"))
        root, names = self.ledger(**sc["already_long_and_no_price"][0])
        b1, b2 = (_summary(root / n / f"book_{i}.receipt.json") for i, n in enumerate(names, 1))
        self.assertEqual(b1["noActions"], [{"asset": "JUP", "action": "NONE", "why": "no observed price \u2014 cannot fill honestly (fail closed)"}])
        self.assertEqual(sorted(x["why"] for x in b2["noActions"]), ["already long \u2014 no pyramiding in v1", "no open position to exit"])

    def test_unverified_signal_is_excluded_not_booked(self):
        runs = [([("SOL", "ENTER_LONG", "ALLOWED", 100), ("JUP", "ENTER_LONG", "ALLOWED", 2)], True)]
        root, names = self.ledger(runs=runs, tamper={(0, "signal_JUP_1.receipt.json")})
        b1 = _summary(root / names[0] / "book_1.receipt.json")
        self.assertEqual(b1["inputs"]["excludedSignals"], {"count": 1, "files": ["signal_JUP_1.receipt.json"]})
        self.assertEqual([f["asset"] for f in b1["fills"]], ["SOL"])
        lines = []
        self.assertTrue(vpy.verify_book(str(root), self.key.spki, out=lines.append), lines)

    def test_book_seq_must_follow_run_dir_order(self):
        names = ["20260202T000000Z_run2", "20260201T000000Z_run1"]
        root, _ = self.ledger(runs=TRADE_RUNS, names=names)
        lines = []
        self.assertFalse(vpy.verify_book(str(root), self.key.spki, out=lines.append))
        self.assertTrue(any("run dir 20260201T000000Z_run1 not after 20260202T000000Z_run2" in l for l in lines), lines)

    def test_exit_then_reentry_resets_cost_basis(self):
        runs = [([("SOL", "ENTER_LONG", "ALLOWED", 100)], True),
                ([("SOL", "EXIT_LONG", "ALLOWED", 110, "1"), ("SOL", "ENTER_LONG", "ALLOWED", 110, "2")], True)]
        root, names = self.ledger(runs=runs)
        b2 = _summary(root / names[1] / "book_2.receipt.json")
        self.assertEqual([f["side"] for f in b2["fills"]], ["SELL", "BUY"])
        self.assertEqual(b2["state"]["positions"]["SOL"]["costMicro"], str(vpy.to_micro(float(b2["fills"][1]["notionalUsd"]))))

    def test_undeclared_run_dir_before_genesis_is_refused(self):
        root, names = self.ledger()
        early = root / "20260100T000000Z_run0"
        early.mkdir()
        lines = []
        self.assertFalse(vpy.verify_book(str(root), self.key.spki, out=lines.append))
        self.assertTrue(any("preBookRunDirs do not match" in l for l in lines), lines)

    def scenarios(self):
        def lie(field, fn):
            return {"edits": {1: lambda b: fn(b[field])}}
        frac = dict(BOOK_CONFIG, entryFractionBps=25.5)
        return {
            "trade_round_trip": ({}, True),
            "tie_price": ({"runs": [([("PYTH", "ENTER_LONG", "ALLOWED", 0.0078125)], True)]}, True),
            "unpriced_open_position": ({"runs": [([("SOL", "ENTER_LONG", "ALLOWED", 100)], True), ([("SOL", "HOLD", "ALLOWED", None), ("JUP", "ENTER_LONG", "ALLOWED", 2)], True)]}, True),
            "insufficient_cash": ({"runs": [([(s, "ENTER_LONG", "ALLOWED", 1 + i) for i, s in enumerate(["A1", "B2", "C3", "D4", "E5", "F6", "G7", "H8", "I9", "J10", "K11", "L12"])], True)],
                                   "config": dict(BOOK_CONFIG, entryFractionBps=5000)}, True),
            "already_long_and_no_price": ({"runs": [([("SOL", "ENTER_LONG", "ALLOWED", 100), ("JUP", "ENTER_LONG", "ALLOWED", None)], True),
                                                    ([("SOL", "ENTER_LONG", "ALLOWED", 101), ("JUP", "EXIT_LONG", "ALLOWED", 2)], True)]}, True),
            "skipped_run_declared": ({"runs": [TRADE_RUNS[0], ([("SOL", "HOLD", "ALLOWED", 105)], False), TRADE_RUNS[1]]}, True),
            "pre_book_dirs": ({"pre": 2}, True),
            "fills_lie": (lie("fills", lambda f: f[0].__setitem__("qtyE9", "9980039921")), False),
            "state_lie": (lie("state", lambda s: s.__setitem__("cashMicro", "9000000001")), False),
            "mark_lie": (lie("mark", lambda m: m.__setitem__("equityUsd", "9999.000000")), False),
            "noactions_lie": (lie("noActions", lambda n: n.pop()), False),
            "inputs_lie": (lie("inputs", lambda i: i["decisions"][0].__setitem__("priceUsd", 99)), False),
            "config_drift": ({"edits": {2: lambda b: b.__setitem__("config", dict(BOOK_CONFIG, entryFractionBps=999))}}, False),
            "skipped_lie": ({"runs": [TRADE_RUNS[0], ([("SOL", "HOLD", "ALLOWED", 105)], False), TRADE_RUNS[1]], "edits": {2: lambda b: b.__setitem__("skippedRunDirs", [])}}, False),
            "prebook_lie": ({"pre": 1, "edits": {1: lambda b: b.__setitem__("preBookRunDirs", [])}}, False),
            "wrong_rundir": ({"edits": {2: lambda b: b.__setitem__("runDir", "elsewhere")}}, False),
            "prev_lie": ({"edits": {2: lambda b: b["prev"].__setitem__("sha256", "0" * 64)}}, False),
            "seq_gap": ({"edits": {2: lambda b: b.__setitem__("seq", 3)}}, False),
            "fractional_entry_bps": ({"config": frac}, False),
            "incomplete_config": ({"config": {"costModel": {"feeBps": 10}, "entryFractionBps": 1000, "startingCashUsd": 10000}}, False),
        }

    def _build(self, kw):
        kw = dict(kw)
        if kw.get("config", BOOK_CONFIG)["entryFractionBps"] == 25.5 or "slippageBps" not in kw.get("config", BOOK_CONFIG)["costModel"]:
            cfg = kw.pop("config")
            root, names = self.ledger(**kw)
            for n in names:
                for p in (root / n).glob("book_*.receipt.json"):
                    p.unlink()
            # re-emit unreplayable books directly: the generator itself cannot replay this config
            prev = None
            for seq, n in enumerate([x for x in names], 1):
                body = {"kind": "szl-quant-book", "v": 1, "seq": seq, "prev": prev, "runDir": n, "config": cfg, "generatedAtIso": "x",
                        "inputs": {}, "fills": [], "noActions": [], "state": {"cashMicro": "0", "positions": {}}, "mark": {}}
                if seq == 1:
                    body["preBookRunDirs"] = []
                else:
                    body["skippedRunDirs"] = []
                raw = json.dumps(self.key.envelope(payload_of(statement(summary=body, predicate_type="https://szl.holdings/quant/book/v1")))).encode()
                (root / n / f"book_{seq}.receipt.json").write_bytes(raw)
                prev = {"file": f"book_{seq}.receipt.json", "runDir": n, "sha256": hashlib.sha256(raw).hexdigest()}
            return root
        return self.ledger(**kw)[0]

    def test_python_book_verdicts(self):
        for name, (kw, want) in self.scenarios().items():
            root = self._build(kw)
            lines = []
            self.assertEqual(vpy.verify_book(str(root), self.key.spki, out=lines.append), want, (name, lines))

    def test_fractional_entry_bps_is_a_replay_error_with_v8_message(self):
        root = self._build(self.scenarios()["fractional_entry_bps"][0])
        lines = []
        self.assertFalse(vpy.verify_book(str(root), self.key.spki, out=lines.append))
        self.assertTrue(any("replay threw \u2014 The number 25.5 cannot be converted to a BigInt because it is not an integer" in l for l in lines), lines)

    def test_malformed_previous_state_aborts_like_verify_mjs(self):
        root, _ = self.ledger(edits={1: lambda b: b["state"].__setitem__("cashMicro", "abc")})
        code, out = run_py(["--pubkey", str(self.pin), "--book", str(root)])
        self.assertEqual((code, [l for l in out.splitlines() if "BOOK" in l]), (1, []))

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_identical_book_report_to_verify_mjs(self):
        for name, (kw, _) in self.scenarios().items():
            root = self._build(kw)
            jcode, jout = run_node(["--pubkey", str(self.pin), "--book", str(root)])
            pcode, pout = run_py(["--pubkey", str(self.pin), "--book", str(root)])
            jl = [l.strip() for l in jout.splitlines() if "BOOK" in l]
            pl = [l.strip() for l in pout.splitlines() if "BOOK" in l]
            self.assertEqual((pl, pcode), (jl, jcode), name)

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_malformed_previous_state_exit_code_matches_verify_mjs(self):
        root, _ = self.ledger(edits={1: lambda b: b["state"].__setitem__("cashMicro", "abc")})
        jcode, jout = run_node(["--pubkey", str(self.pin), "--book", str(root)])
        self.assertEqual((jcode, [l for l in jout.splitlines() if "BOOK" in l]), (1, []))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is required for signature tests")
class PublishedBookTests(unittest.TestCase):
    def test_mid_chain_run_dir_alone_aborts_like_verify_mjs(self):
        """The fixture is one mid-chain run dir (book seq 8): there is no previous link to
        replay from, so verify.mjs throws reading links[-1].body and exits 1; so does the twin."""
        with self.assertRaises(TypeError):
            vpy.verify_book(str(FIXTURES), vpy.load_pin(str(ENGINE_PIN)), out=lambda _l: None)
        code, out = run_py(["--pubkey", str(ENGINE_PIN), "--book", str(FIXTURES)])
        self.assertEqual((code, [l for l in out.splitlines() if "BOOK" in l]), (1, []))

    @unittest.skipUnless(NODE, "node is required for verify.mjs parity")
    def test_published_book_report_matches_verify_mjs(self):
        args = ["--pubkey", str(ENGINE_PIN), "--book", str(FIXTURES)]
        jcode, jout = run_node(args)
        pcode, pout = run_py(args)
        self.assertEqual(([l.strip() for l in pout.splitlines() if "BOOK" in l], pcode),
                         ([l.strip() for l in jout.splitlines() if "BOOK" in l], jcode))


class CliAndPinTests(unittest.TestCase):
    def test_usage_and_unsupported_flags_exit_2(self):
        self.assertEqual(run_py([])[0], 2)
        self.assertEqual(run_py(["--witness", "."])[0], 2)
        self.assertEqual(run_py(["--dir"])[0], 2)

    def test_bad_pins_exit_2(self):
        d = tmpdir(self)
        pin = json.loads(ENGINE_PIN.read_text(encoding="utf-8"))
        for i, bad in enumerate([dict(pin, keyId="0" * 16), dict(pin, alg="rsa"), dict(pin, kind="other"), dict(pin, publicKeySpkiBase64="%%%")]):
            p = d / f"pin{i}.json"
            p.write_text(json.dumps(bad), encoding="utf-8")
            self.assertEqual(run_py(["--pubkey", str(p), "--dir", str(d)])[0], 2, i)


if __name__ == "__main__":
    unittest.main()
