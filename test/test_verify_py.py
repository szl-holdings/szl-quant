# SPDX-License-Identifier: Apache-2.0
"""Parity tests: verify/verify.py against verify/verify.mjs (stdlib unittest).

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


class CliAndPinTests(unittest.TestCase):
    def test_usage_and_unsupported_flags_exit_2(self):
        self.assertEqual(run_py([])[0], 2)
        self.assertEqual(run_py(["--book", "ledger"])[0], 2)
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
