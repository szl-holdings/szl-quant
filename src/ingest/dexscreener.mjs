/**
 * ingest/dexscreener.mjs — live Solana pair snapshots from the Dexscreener
 * PUBLIC API (keyless; pairs endpoints ~300 req/min). External feed ⇒ every
 * value REPORTED. Any failure ⇒ honest UNAVAILABLE, never invented.
 */

const BASE = 'https://api.dexscreener.com';

/**
 * Fetch pair snapshots by token addresses (Solana), max 30 per call.
 * Returns { ok, pairs?, unavailable? }. Each pair snapshot is REPORTED.
 */
export async function fetchSolanaPairs(tokenAddresses) {
  if (!Array.isArray(tokenAddresses) || tokenAddresses.length === 0 || tokenAddresses.length > 30) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'tokenAddresses must be 1..30 (dexscreener limit)' } };
  }
  const url = `${BASE}/tokens/v1/solana/${tokenAddresses.join(',')}`;
  let res;
  try {
    res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'szl-quant/1.0 (advisory research; paper-only)' } });
  } catch (e) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `dexscreener fetch failed: ${e.message}` } };
  }
  if (!res.ok) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `dexscreener HTTP ${res.status}` } };
  }
  const arr = await res.json().catch(() => null);
  if (!Array.isArray(arr)) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'dexscreener: non-array response' } };
  }
  const observedAtMs = Date.now();
  const pairs = arr.map((p) => ({
    label: 'REPORTED',
    observedAtMs,
    chainId: p.chainId ?? null,
    dexId: p.dexId ?? null,
    pairAddress: p.pairAddress ?? null,
    baseSymbol: p.baseToken?.symbol ?? null,
    baseAddress: p.baseToken?.address ?? null,
    quoteSymbol: p.quoteToken?.symbol ?? null,
    priceUsd: Number.isFinite(Number(p.priceUsd)) ? Number(p.priceUsd) : null,
    liquidityUsd: Number.isFinite(p.liquidity?.usd) ? p.liquidity.usd : null,
    volume24hUsd: Number.isFinite(p.volume?.h24) ? p.volume.h24 : null,
    priceChange: {
      h1: Number.isFinite(p.priceChange?.h1) ? p.priceChange.h1 : null,
      h6: Number.isFinite(p.priceChange?.h6) ? p.priceChange.h6 : null,
      h24: Number.isFinite(p.priceChange?.h24) ? p.priceChange.h24 : null,
    },
    url: p.url ?? null,
  }));
  return { ok: true, pairs };
}

/** Pick, per base token, the pair with the deepest liquidity (honest tiebreak). */
export function deepestPairs(pairs) {
  const best = new Map();
  for (const p of pairs) {
    if (!p.baseAddress) continue;
    const cur = best.get(p.baseAddress);
    if (!cur || (p.liquidityUsd ?? -1) > (cur.liquidityUsd ?? -1)) best.set(p.baseAddress, p);
  }
  return [...best.values()];
}
