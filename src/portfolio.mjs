/**
 * portfolio.mjs — deterministic PAPER portfolio accounting.
 *
 * No orders, no execution, no custody. Fills are simulated at the next
 * observed price with an explicit MODELED cost (fee + slippage in bps).
 * All money math uses integer micro-USD (1e-6 USD) to stay deterministic —
 * no float accumulation drift; identical inputs ⇒ identical books.
 */

const MICRO = 1_000_000n;

export function toMicroUsd(x) {
  // deterministic decimal→micro conversion via string, avoids float drift
  if (!Number.isFinite(x)) throw new Error('non-finite amount');
  const s = x.toFixed(6);
  const neg = s.startsWith('-');
  const [ints, fracs] = (neg ? s.slice(1) : s).split('.');
  const v = BigInt(ints) * MICRO + BigInt(fracs);
  return neg ? -v : v;
}
export function microToUsdString(m) {
  const neg = m < 0n;
  const a = neg ? -m : m;
  return `${neg ? '-' : ''}${a / MICRO}.${(a % MICRO).toString().padStart(6, '0')}`;
}

/**
 * Validate the MODELED paper cost contract.
 *
 * Fees and slippage cannot be negative because that would manufacture a
 * rebate/price improvement that the declared model never measured. Their
 * combined rate must remain below 100% so SELL effective prices stay
 * strictly positive. This is a mathematical admission boundary, not a claim
 * that any particular nonnegative bps assumption is realistic.
 */
export function validateCostModel(costModel) {
  if (!costModel ||
      !Number.isFinite(costModel.feeBps) || costModel.feeBps < 0 ||
      !Number.isFinite(costModel.slippageBps) || costModel.slippageBps < 0) {
    throw new Error('costModel feeBps/slippageBps must be finite and nonnegative (MODELED; fail closed)');
  }
  const totalBps = costModel.feeBps + costModel.slippageBps;
  if (!Number.isFinite(totalBps) || totalBps >= 10_000) {
    throw new Error('combined MODELED cost must be below 10000 bps (fail closed)');
  }
  return { feeBps: costModel.feeBps, slippageBps: costModel.slippageBps };
}

/**
 * Create a paper book.
 * costModel: { feeBps, slippageBps } — MODELED, stated in every receipt.
 */
export function makeBook({ startingCashUsd, costModel }) {
  if (!(startingCashUsd > 0)) throw new Error('startingCashUsd must be > 0');
  const admittedCostModel = validateCostModel(costModel);
  return {
    cashMicro: toMicroUsd(startingCashUsd),
    positions: {},          // asset → { qtyE9: bigint (1e-9 units), costMicro: bigint }
    fills: [],
    costModel: admittedCostModel,
  };
}

export const QTY = 1_000_000_000n; // 1e-9 asset units

/**
 * Apply a paper fill. Costs (fee+slippage) are embedded in the effective
 * price — charged exactly once, never double-counted.
 *   BUY:  { notionalUsd } — cash out; qty received at effPrice (above market).
 *   SELL: { qtyE9 }       — position out; proceeds at effPrice (below market).
 * Returns the fill record.
 */
export function paperFill(book, { asset, side, notionalUsd, qtyE9: sellQtyE9, price, atIso, reason }) {
  if (!(price > 0)) throw new Error('fill requires observed price > 0');
  const admittedCostModel = validateCostModel(book?.costModel);
  const costRate = (admittedCostModel.feeBps + admittedCostModel.slippageBps) / 10_000;
  const pos = book.positions[asset] ?? { qtyE9: 0n, costMicro: 0n };
  let fill;

  if (side === 'BUY') {
    if (!(notionalUsd > 0)) throw new Error('BUY requires notionalUsd > 0');
    const notionalMicro = toMicroUsd(notionalUsd);
    if (book.cashMicro < notionalMicro) throw new Error('insufficient paper cash (no leverage in paper book)');
    const effPrice = price * (1 + costRate);
    const qtyE9 = (notionalMicro * QTY) / toMicroUsd(effPrice);
    const grossQtyE9 = (notionalMicro * QTY) / toMicroUsd(price);
    const modeledCostMicro = ((grossQtyE9 - qtyE9) * toMicroUsd(price)) / QTY;
    book.cashMicro -= notionalMicro;
    pos.qtyE9 += qtyE9;
    pos.costMicro += notionalMicro;
    fill = {
      asset, side,
      notionalUsd: microToUsdString(notionalMicro),
      price: String(price),
      effectivePrice: effPrice.toFixed(10),
      qtyE9: qtyE9.toString(),
      modeledCostUsd: microToUsdString(modeledCostMicro),
      costModel: { ...admittedCostModel, label: 'MODELED' },
      atIso, reason,
    };
  } else if (side === 'SELL') {
    const q = typeof sellQtyE9 === 'bigint' ? sellQtyE9 : BigInt(sellQtyE9 ?? 0);
    if (!(q > 0n)) throw new Error('SELL requires qtyE9 > 0');
    if (pos.qtyE9 < q) throw new Error('insufficient paper position (no shorting in v1 paper book)');
    const effPrice = price * (1 - costRate);
    const proceedsMicro = (q * toMicroUsd(effPrice)) / QTY;
    const grossMicro = (q * toMicroUsd(price)) / QTY;
    book.cashMicro += proceedsMicro;
    pos.qtyE9 -= q;
    if (pos.qtyE9 === 0n) pos.costMicro = 0n;
    fill = {
      asset, side,
      notionalUsd: microToUsdString(proceedsMicro),
      price: String(price),
      effectivePrice: effPrice.toFixed(10),
      qtyE9: q.toString(),
      modeledCostUsd: microToUsdString(grossMicro - proceedsMicro),
      costModel: { ...admittedCostModel, label: 'MODELED' },
      atIso, reason,
    };
  } else {
    throw new Error(`unknown side ${side}`);
  }

  book.positions[asset] = pos;
  book.fills.push(fill);
  return fill;
}

/** Mark the book to observed prices. Missing price ⇒ position is UNAVAILABLE (no value invented). */
export function markToMarket(book, pricesByAsset, atIso) {
  const positions = [];
  let equityMicro = book.cashMicro;
  let unpriced = 0;
  for (const [asset, pos] of Object.entries(book.positions)) {
    if (pos.qtyE9 === 0n) continue;
    const p = pricesByAsset[asset];
    if (!(p > 0)) {
      positions.push({ asset, qtyE9: pos.qtyE9.toString(), value: { label: 'UNAVAILABLE', note: 'no observed price at mark time' } });
      unpriced++;
      continue;
    }
    const valueMicro = (pos.qtyE9 * toMicroUsd(p)) / QTY;
    equityMicro += valueMicro;
    positions.push({ asset, qtyE9: pos.qtyE9.toString(), markPrice: String(p), valueUsd: microToUsdString(valueMicro) });
  }
  return {
    atIso,
    cashUsd: microToUsdString(book.cashMicro),
    positions,
    // equity is only honest if every open position had an observed price
    equityUsd: unpriced === 0 ? microToUsdString(equityMicro) : null,
    equityNote: unpriced === 0 ? undefined : `${unpriced} position(s) unpriced — equity not computable (honest empty)`,
    fillsSoFar: book.fills.length,
  };
}
