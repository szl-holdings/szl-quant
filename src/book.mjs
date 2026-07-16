/**
 * book.mjs — the STATEFUL paper book: a cross-run paper fund whose every
 * state transition is signed, prev-hash-linked, and REPLAYABLE by the
 * independent verifier from the signed signal receipts alone.
 *
 * Track record scores what signals said; the book accounts what a paper
 * fund following them would hold. Rules (frozen v1, verifier reimplements
 * them byte-for-byte):
 *   - Only DSSE-VERIFIED decisions move the book (tampered → excluded).
 *   - ALLOWED ENTER_LONG buys entryFractionBps of current equity, at the
 *     decision-time REPORTED price with MODELED bps costs; no leverage,
 *     no pyramiding, no shorting.
 *   - ALLOWED EXIT_LONG sells the full position. BLOCKED anything → the
 *     gates hold the book (fail closed, honest no-action note).
 *   - Missing price ⇒ no fill, position stays, equity may go null —
 *     honest empty, never a made-up mark.
 *   - Config is inherited from the chain (genesis pins it); a silent
 *     mid-stream config change is impossible without breaking replay.
 *
 * HONEST LIMITS (stated in every receipt): fills are simulated at the
 * decision-time DEX snapshot price + modeled bps — no depth, latency or
 * partial-fill realism. Equity is MODELED. Paper only. Never real funds.
 */
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { makeBook, paperFill, markToMarket, toMicroUsd, microToUsdString, QTY } from './portfolio.mjs';

export const BOOK_FILE_RE = /^book_\d+\.receipt\.json$/;
export const DEFAULT_BOOK_CONFIG = Object.freeze({
  startingCashUsd: 10_000,
  entryFractionBps: 1000, // 10% of current equity per new entry
  costModel: Object.freeze({ feeBps: 30, slippageBps: 20 }), // MODELED, stated — same declared assumption as the backtests
});
const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/** Scan the ledger for run dirs + existing book receipts (IO injected). */
export function scanLedgerForBook(ledgerDir, { readdirSync, readFileSync }) {
  let dirents;
  try { dirents = readdirSync(ledgerDir, { withFileTypes: true }); }
  catch { return { dirs: [], books: [], prevBook: null }; }
  const dirs = dirents.filter((e) => e.isDirectory()).map((e) => e.name).sort();
  const books = [];
  for (const dir of dirs) {
    const names = readdirSync(join(ledgerDir, dir), { withFileTypes: true })
      .filter((e) => e.isFile()).map((e) => e.name).sort();
    for (const name of names) {
      if (!BOOK_FILE_RE.test(name)) continue;
      const bytes = readFileSync(join(ledgerDir, dir, name));
      let body = null;
      try {
        const env = JSON.parse(bytes.toString('utf8'));
        body = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'))?.predicate?.summary ?? null;
      } catch { /* unreadable book receipt: surfaces as seq null → fork refusal */ }
      books.push({ runDir: dir, file: name, sha256: sha256Hex(bytes), body, seq: body?.seq ?? null });
    }
  }
  books.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  return { dirs, books, prevBook: books.length ? books[books.length - 1] : null };
}

/** Extract the exact decision fields the book acts on, from a VERIFIED statement. */
export function decisionForBook(file, statement) {
  const dec = statement?.predicate?.decision;
  if (!dec?.asset?.symbol || !dec.proposedAction || !dec.verdict) return null;
  return {
    file,
    symbol: dec.asset.symbol,
    proposedAction: dec.proposedAction,
    verdict: dec.verdict,
    priceUsd: dec.snapshot?.priceUsd ?? null,
    observedAtIso: dec.snapshot?.observedAtIso ?? null,
  };
}

/** BigInt state from a book body's serialized state (strings → BigInt). */
export function resurrectState(body) {
  const positions = {};
  for (const [asset, p] of Object.entries(body?.state?.positions ?? {})) {
    positions[asset] = { qtyE9: BigInt(p.qtyE9), costMicro: BigInt(p.costMicro) };
  }
  return { cashMicro: BigInt(body.state.cashMicro), positions };
}

function serializeState(book) {
  const positions = {};
  for (const [asset, p] of Object.entries(book.positions)) {
    if (p.qtyE9 > 0n) positions[asset] = { qtyE9: p.qtyE9.toString(), costMicro: p.costMicro.toString() };
  }
  return { cashMicro: book.cashMicro.toString(), positions };
}

/** Equity right now, or null if ANY open position lacks a price (fail closed). */
function equityNowMicro(book, prices) {
  let eq = book.cashMicro;
  for (const [asset, p] of Object.entries(book.positions)) {
    if (p.qtyE9 === 0n) continue;
    const price = prices[asset];
    if (!(price > 0)) return null;
    eq += (p.qtyE9 * toMicroUsd(price)) / QTY;
  }
  return eq;
}

/**
 * Build the next book body (pure, deterministic). Decisions must already
 * be DSSE-verified by the caller — this function trusts its inputs are
 * signed facts and applies the frozen v1 rules to them.
 */
export function buildBookBody({ prevBook, decisions, runDir, nowIso, allRunDirs, excludedSignals, config = DEFAULT_BOOK_CONFIG }) {
  if (prevBook && !Number.isInteger(prevBook.body?.seq)) {
    throw new Error('previous book receipt has no readable seq — refusing to fork the book (fail closed)');
  }
  const seq = prevBook ? prevBook.body.seq + 1 : 1;
  const engineDefaults = { ...config, costModel: { ...config.costModel } };
  const effConfig = prevBook ? prevBook.body.config : engineDefaults;
  const configNote = prevBook && JSON.stringify(prevBook.body.config) !== JSON.stringify(engineDefaults)
    ? 'config INHERITED from the existing book chain; engine defaults differ — changing config requires an explicit new book, never a silent drift'
    : undefined;

  const book = prevBook
    ? { ...resurrectState(prevBook.body), fills: [], costModel: { ...effConfig.costModel } }
    : makeBook({ startingCashUsd: effConfig.startingCashUsd, costModel: { ...effConfig.costModel } });

  const sorted = [...decisions].sort((a, b) => (a.symbol < b.symbol ? -1 : a.symbol > b.symbol ? 1 : 0));
  const prices = {};
  for (const d of sorted) if (d.priceUsd > 0) prices[d.symbol] = d.priceUsd;

  const noActions = [];
  for (const d of sorted) {
    const pos = book.positions[d.symbol];
    const held = !!pos && pos.qtyE9 > 0n;
    if (d.verdict !== 'ALLOWED') {
      noActions.push({ asset: d.symbol, action: 'NONE', why: `decision ${d.verdict} — fail closed, the gates hold the book` });
      continue;
    }
    if (d.proposedAction === 'ENTER_LONG') {
      if (held) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'already long — no pyramiding in v1' }); continue; }
      if (!(d.priceUsd > 0)) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no observed price — cannot fill honestly (fail closed)' }); continue; }
      const eq = equityNowMicro(book, prices);
      if (eq === null) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'an open position is unpriced — equity not computable, no new entries (fail closed)' }); continue; }
      const allocMicro = (eq * BigInt(effConfig.entryFractionBps)) / 10_000n;
      if (allocMicro <= 0n || allocMicro > book.cashMicro) {
        noActions.push({ asset: d.symbol, action: 'SKIPPED_INSUFFICIENT_CASH', why: `entry needs ${microToUsdString(allocMicro)} USD but paper cash is ${microToUsdString(book.cashMicro)} — no leverage, honest skip` });
        continue;
      }
      paperFill(book, { asset: d.symbol, side: 'BUY', notionalUsd: Number(microToUsdString(allocMicro)), price: d.priceUsd, atIso: d.observedAtIso, reason: 'ALLOWED ENTER_LONG' });
    } else if (d.proposedAction === 'EXIT_LONG') {
      if (!held) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no open position to exit' }); continue; }
      if (!(d.priceUsd > 0)) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no observed price — cannot exit honestly (fail closed, position remains)' }); continue; }
      paperFill(book, { asset: d.symbol, side: 'SELL', qtyE9: book.positions[d.symbol].qtyE9, price: d.priceUsd, atIso: d.observedAtIso, reason: 'ALLOWED EXIT_LONG' });
    } else {
      noActions.push({ asset: d.symbol, action: 'NONE', why: `${d.proposedAction} — no book action` });
    }
  }

  const mark = markToMarket(book, prices, nowIso);
  const before = (allRunDirs ?? []).filter((d) => d < runDir);
  return {
    kind: 'szl-quant-book',
    v: 1,
    seq,
    generatedAtIso: nowIso,
    runDir,
    prev: prevBook ? { runDir: prevBook.runDir, file: prevBook.file, sha256: prevBook.sha256 } : null,
    config: effConfig,
    ...(configNote ? { configNote } : {}),
    ...(prevBook
      ? { skippedRunDirs: before.filter((d) => d > prevBook.runDir) }
      : { preBookRunDirs: before }),
    inputs: {
      signalFiles: sorted.map((d) => d.file).sort(),
      decisions: sorted.map(({ file, symbol, proposedAction, verdict, priceUsd, observedAtIso }) => ({ file, symbol, proposedAction, verdict, priceUsd, observedAtIso })),
      excludedSignals: excludedSignals ?? { count: 0, files: [] },
    },
    fills: book.fills,
    noActions,
    state: serializeState(book),
    mark,
    labels: {
      fills: 'MODELED (simulated at REPORTED decision-time price + modeled bps costs)',
      equity: mark.equityUsd === null
        ? 'UNAVAILABLE (unpriced positions — honest empty, nothing invented)'
        : 'MODELED (paper simulation over REPORTED marks — NOT real funds)',
    },
    note: prevBook
      ? 'stateful paper book — extends the previous receipt by sha256 of its bytes; the transition is replayable from the signed signal receipts in this run dir'
      : 'GENESIS book — the paper fund starts here; earlier runs remain advisory-only (listed below, never backfilled)',
    limits: 'paper-only simulation: fills at decision-time REPORTED DEX price with MODELED fee+slippage bps; no depth/latency/partial-fill realism; equity is MODELED, never real funds; a run missed by the book stays un-booked (declared, never backfilled)',
  };
}
