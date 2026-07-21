#!/usr/bin/env node
/**
 * tools/sft-export.mjs — receipts → SFT dataset with signed lineage.
 *
 * Every training row is derived DETERMINISTICALLY from a generation-7
 * backtest receipt's content-addressed dataset archive: we replay the
 * exact bars the receipt pinned and record the engine's actual decision
 * at each step. No row is written that cannot be traced to a DSSE-signed
 * receipt and recomputed from archived bytes.
 *
 * Honesty (LAW):
 *  - rows are DERIVED artifacts: deterministic replay over a REPORTED
 *    feed archive whose backtest context is MEASURED — the manifest and
 *    dataset card must say exactly that, never "human-labeled";
 *  - ABSTAIN rows are genuine engine abstentions (insufficient history),
 *    not synthetic paraphrases;
 *  - HOLD decisions dominate raw replays, so they are downsampled by a
 *    fixed, declared, deterministic rule (every Nth per stream) — stated
 *    in the manifest; nothing else is filtered;
 *  - conviction values pass through capTrust (≤ 0.97) untouched;
 *  - the export fails CLOSED: any archive hash mismatch, missing file,
 *    or non-verifying source receipt aborts the whole export.
 *
 * Output (under --out, default sft/):
 *   quant_sft_v1.jsonl            one canonical-JSON row per line
 *   quant_sft_v1.manifest.json    counts, sources, jsonlSha256, rules
 *   quant_sft_v1.manifest.receipt.json  DSSE receipt over the manifest
 *
 * Usage:
 *   SZL_QUANT_KEY=path/to/key.pem node tools/sft-export.mjs [--out sft/] [--repo-root .]
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../src/canonical-json.mjs';
import { evaluate } from '../src/strategy.mjs';
import { periodReturn, zScore, annualizedVol } from '../src/formulas.mjs';
import { datasetArchivePath } from '../src/datasets.mjs';
import { signReceipt } from '../src/receipts.mjs';
import { verifyEnvelope } from '../src/dsse.mjs';
import { loadPrivateKey, loadPublicKeyFromSpkiBase64, keyIdFromPublicKey } from '../src/keys.mjs';
import { TRUST_CEILING } from '../src/canon.mjs';

const HOLD_KEEP_EVERY = 7;       // declared downsample rule for HOLD rows
const ABSTAIN_WINDOW_OFFSETS = [0, 10]; // warmup-1-offset windows per cell → genuine ABSTAINs

const SYSTEM_PROMPT = [
  'You are SZL-Quant, a doctrine-governed advisory research analyst. LAW:',
  'label every value (LIVE/MEASURED/REPORTED/MODELED/HEURISTIC/DEMO/UNAVAILABLE);',
  'never invent numbers; conviction is ADVISORY (Λ = Conjecture 1) and capped at 0.97;',
  'if evidence is missing or insufficient, ABSTAIN — an absent value carries no value;',
  'risk gates fail closed with honest BLOCKED verdicts; paper-only; not financial advice.',
].join(' ');

const FIXED_CAVEATS = [
  'components are HEURISTIC transforms of a REPORTED venue feed',
  'Λ aggregation is ADVISORY (Conjecture 1, unproven uniqueness)',
  'conviction ceiling 0.97 — proven trust is locked false',
  'paper-only advisory research; not financial advice',
];

function sha256HexBytes(buf) { return createHash('sha256').update(buf).digest('hex'); }

function warmupOf(params) {
  return Math.max(params.momentumLookback, params.zWindow, params.volWindow) + 2;
}

/** The user-visible evidence block — recomputed the same way evaluate() does. */
function evidenceAt(window, params) {
  const closes = window.map((s) => s.close);
  return {
    trailingReturn: periodReturn(closes, params.momentumLookback),
    zScore: zScore(closes, params.zWindow),
    annualizedVol: annualizedVol(closes, params.volWindow),
    nObservations: closes.length - 1,
  };
}

function rowFrom({ asset, atIso, params, evidence, sig, provenance }) {
  const assistant = sig.action === 'ABSTAIN'
    ? { action: 'ABSTAIN', note: sig.note, caveats: FIXED_CAVEATS }
    : {
        action: sig.action,
        components: sig.components,
        conviction: sig.conviction,
        lambda: sig.lambda,
        caveats: FIXED_CAVEATS,
      };
  return {
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: JSON.stringify({ task: 'advisory-signal-decision', asset, asOfIso: atIso, params, evidence }) },
      { role: 'assistant', content: JSON.stringify(assistant) },
    ],
    provenance,
  };
}

export function exportSft({ repoRoot, outDir }) {
  const receiptsDir = join(repoRoot, 'receipts');
  const files = readdirSync(receiptsDir).filter((f) => f.startsWith('backtest_') && f.endsWith('.receipt.json')).sort();
  if (files.length === 0) throw new Error('no backtest receipts found — nothing to export (fail closed)');

  // Source receipts must VERIFY against the committed engine pubkey before
  // a single row is derived — a forged receipt file must not seed training data.
  const pubJson = JSON.parse(readFileSync(join(repoRoot, 'keys/engine_pubkey.json'), 'utf8'));
  const enginePub = loadPublicKeyFromSpkiBase64(pubJson.publicKeySpkiBase64);
  const engineKeyId = keyIdFromPublicKey(enginePub);

  const rows = [];
  const sources = [];
  const counts = { ENTER_LONG: 0, EXIT_LONG: 0, HOLD: 0, ABSTAIN: 0 };

  for (const f of files) {
    const envBytes = readFileSync(join(receiptsDir, f));
    const env = JSON.parse(envBytes.toString('utf8'));
    const v = verifyEnvelope(env, enginePub);
    if (!v.ok) throw new Error(`${f}: source receipt signature does NOT verify against the engine pubkey (${v.reason ?? 'bad signature'}) — refusing to derive training rows (fail closed)`);
    if (env.signatures?.[0]?.keyid && env.signatures[0].keyid !== engineKeyId) {
      throw new Error(`${f}: signed by keyid ${env.signatures[0].keyid}, expected engine ${engineKeyId} — fail closed`);
    }
    const stmt = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    const sum = stmt?.predicate?.summary;
    if (!sum?.datasetArchive?.path || !sum?.dataset?.sha256) {
      throw new Error(`${f}: not a generation-7 receipt (no datasetArchive) — refusing to derive rows from unpinned inputs (fail closed)`);
    }
    const expectSha = sum.dataset.sha256;
    const canonicalPath = datasetArchivePath(expectSha);
    if (sum.datasetArchive.path !== canonicalPath) {
      throw new Error(`${f}: datasetArchive.path is not the canonical content address (fail closed)`);
    }
    const seriesBytes = readFileSync(resolve(repoRoot, canonicalPath));
    const gotSha = sha256HexBytes(seriesBytes);
    if (gotSha !== expectSha) throw new Error(`${f}: archived dataset hash mismatch (${gotSha.slice(0, 12)}… ≠ ${expectSha.slice(0, 12)}…) — fail closed`);
    const series = JSON.parse(seriesBytes.toString('utf8'));
    if (sha256HexBytes(canonicalBytes(series)) !== expectSha) {
      throw new Error(`${f}: archive bytes are not canonical JSON of the series — fail closed`);
    }

    const asset = sum.asset;
    const receiptSha = sha256HexBytes(envBytes);
    sources.push({ receiptFile: `receipts/${f}`, receiptSha256: receiptSha, datasetSha256: expectSha, asset, bars: series.length });

    for (const params of sum.method.grid) {
      const warm = warmupOf(params);
      let holdSeen = 0;
      // genuine ABSTAIN rows: windows shorter than warmup
      for (const off of ABSTAIN_WINDOW_OFFSETS) {
        const end = Math.max(2, warm - 1 - off);
        const window = series.slice(0, end);
        const sig = evaluate(window, params);
        if (sig.action !== 'ABSTAIN') continue; // only real abstentions
        const atIso = new Date(window[window.length - 1].tMs).toISOString();
        rows.push(rowFrom({
          asset, atIso, params,
          evidence: evidenceAt(window, params),
          sig,
          provenance: {
            derivation: 'deterministic-abstain-drill', sourceReceipt: `receipts/${f}`, receiptSha256: receiptSha,
            datasetSha256: expectSha, barIndex: end - 1, generator: 'tools/sft-export.mjs v1',
          },
        }));
        counts.ABSTAIN++;
      }
      // replay decisions (same walk as replaySeries: decision at close i)
      for (let i = warm; i < series.length - 1; i++) {
        const window = series.slice(0, i + 1);
        const sig = evaluate(window, params);
        if (sig.action === 'ABSTAIN') continue; // cannot happen past warmup; guard anyway
        if (sig.action === 'HOLD') {
          holdSeen++;
          if (holdSeen % HOLD_KEEP_EVERY !== 0) continue;
        }
        const atIso = new Date(series[i].tMs).toISOString();
        rows.push(rowFrom({
          asset, atIso, params,
          evidence: evidenceAt(window, params),
          sig,
          provenance: {
            derivation: 'deterministic-replay', sourceReceipt: `receipts/${f}`, receiptSha256: receiptSha,
            datasetSha256: expectSha, barIndex: i, generator: 'tools/sft-export.mjs v1',
          },
        }));
        counts[sig.action]++;
      }
    }
  }

  // ceiling audit — fail closed if anything ever exceeds it
  for (const r of rows) {
    const a = JSON.parse(r.messages[2].content);
    if (a.conviction != null && a.conviction > TRUST_CEILING) {
      throw new Error(`row conviction ${a.conviction} exceeds trust ceiling ${TRUST_CEILING} — fail closed`);
    }
  }

  mkdirSync(outDir, { recursive: true });
  const jsonl = rows.map((r) => Buffer.from(canonicalBytes(r)).toString('utf8')).join('\n') + '\n';
  const jsonlPath = join(outDir, 'quant_sft_v1.jsonl');
  writeFileSync(jsonlPath, jsonl);
  const jsonlSha256 = sha256HexBytes(Buffer.from(jsonl, 'utf8'));

  const manifest = {
    version: 'quant-sft-v1',
    generator: 'tools/sft-export.mjs v1',
    generatorSha256: sha256HexBytes(readFileSync(fileURLToPath(import.meta.url))),
    rows: rows.length,
    counts,
    downsampleRule: `HOLD decisions kept 1-in-${HOLD_KEEP_EVERY} per (receipt, grid-cell) stream, deterministic; all ENTER/EXIT/ABSTAIN kept`,
    abstainRule: `probe windows near warmup (length max(2, warmup-1-offset), offsets ${JSON.stringify(ABSTAIN_WINDOW_OFFSETS)}) per grid cell; only genuine engine abstentions kept — probes that decide are skipped, never relabeled`,
    sources,
    jsonlSha256,
    jsonlBytes: Buffer.byteLength(jsonl, 'utf8'),
    honesty: {
      rowsAre: 'DERIVED — deterministic replay of content-addressed dataset archives pinned by DSSE-signed MEASURED backtest receipts; the underlying feed is REPORTED venue history',
      neverInvented: true,
      trustCeiling: TRUST_CEILING,
      note: 'every row carries provenance {sourceReceipt, receiptSha256, datasetSha256, barIndex} and is recomputable bit-exact from the archives (given the generator pinned by generatorSha256)',
      timestampNote: 'row asOfIso = the DECISION bar close; the engine books fills at the NEXT bar close (see src/backtest.mjs) — evidence windows end at the decision bar, no lookahead',
    },
  };
  const manifestPath = join(outDir, 'quant_sft_v1.manifest.json');
  writeFileSync(manifestPath, Buffer.from(canonicalBytes(manifest)).toString('utf8') + '\n');

  return { rows: rows.length, counts, jsonlPath, manifestPath, manifest };
}

function main() {
  const args = process.argv.slice(2);
  const repoRoot = resolve(args.includes('--repo-root') ? args[args.indexOf('--repo-root') + 1] : join(dirname(fileURLToPath(import.meta.url)), '..'));
  const outDir = resolve(repoRoot, args.includes('--out') ? args[args.indexOf('--out') + 1] : 'sft');

  const res = exportSft({ repoRoot, outDir });
  console.log(`rows: ${res.rows}  counts: ${JSON.stringify(res.counts)}`);
  console.log(`jsonl → ${res.jsonlPath}`);
  console.log(`manifest → ${res.manifestPath}`);

  const keyPath = process.env.SZL_QUANT_KEY;
  if (!keyPath) {
    console.error('SZL_QUANT_KEY not set — manifest left UNSIGNED (fail closed: do not publish an unsigned export)');
    process.exitCode = 2;
    return;
  }
  const privateKey = loadPrivateKey(keyPath);
  const pub = JSON.parse(readFileSync(resolve(repoRoot, 'keys/engine_pubkey.json'), 'utf8'));
  const publicKey = loadPublicKeyFromSpkiBase64(pub.publicKeySpkiBase64);
  // subject name/digest MUST be a truthful pair: the digest is over the
  // manifest bytes, so the subject names the manifest. The manifest in turn
  // pins the JSONL via jsonlSha256 (transitive chain, each link honest).
  const { envelope } = signReceipt({
    predicateType: 'https://szl.holdings/quant/sft-export/v1',
    subjectName: 'sft/quant_sft_v1.manifest.json',
    subjectBody: res.manifest,
    predicate: { export: res.manifest },
    privateKey, publicKey,
  });
  const rcptPath = join(outDir, 'quant_sft_v1.manifest.receipt.json');
  writeFileSync(rcptPath, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`signed receipt → ${rcptPath}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
