/**
 * ingest/history.mjs — resilient daily-history fetch with an HONEST
 * fallback chain. CoinGecko public (USD) is primary; Coinbase Exchange
 * public candles (USD) is secondary when CoinGecko fails (its shared
 * public tier throttles hard). Doctrine rules:
 *
 *   - The receipt's dataset block always names the source that actually
 *     served the bytes, and `sourceChain` records every attempt + outcome.
 *   - Sources are NEVER stitched into one series — one series, one source.
 *   - Both down ⇒ UNAVAILABLE (fail closed). No cache, no invention.
 *
 * (Binance was evaluated and rejected for the fallback role: HTTP 451
 * geo-restriction from US egress — see docs/METHODOLOGY.md.)
 */
import { fetchDailyHistory } from './coingecko.mjs';
import { fetchDailyHistoryCoinbase } from './coinbase.mjs';

/**
 * CoinGecko id → Coinbase Exchange product, for engine assets with a LIVE
 * Coinbase market. JUP is deliberately unmapped: the JUP-USD product exists
 * but served zero candles when verified (2026-07-15) — a dead fallback entry
 * would be dishonest. JUP history is CoinGecko-only (honest gap).
 */
export const COINBASE_PRODUCTS = Object.freeze({
  bitcoin: 'BTC-USD',
  ethereum: 'ETH-USD',
  solana: 'SOL-USD',
  bonk: 'BONK-USD',
  dogwifcoin: 'WIF-USD',
  'jito-governance-token': 'JTO-USD',   // candles verified non-empty 2026-07-15
  'pyth-network': 'PYTH-USD',           // candles verified non-empty 2026-07-15
});

/** Solana token address → CoinGecko id (single source of truth for the
 *  live universe's history context; used by paper sessions AND the
 *  track-record scorer so both always resolve assets identically). */
export const HISTORY_IDS_BY_ADDRESS = Object.freeze({
  So11111111111111111111111111111111111111112: 'solana',
  DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: 'bonk',
  EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm: 'dogwifcoin',
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: 'jupiter-exchange-solana',
  jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL: 'jito-governance-token',
  HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3: 'pyth-network',
});

/**
 * Fetch daily history for `coinId`, trying CoinGecko then Coinbase.
 * `deps` is injectable for tests. Returns the shared ingest contract
 * ({ ok, series, dataset } | { ok:false, unavailable }), with
 * dataset.sourceChain / unavailable.sourceChain appended.
 */
export async function fetchDailyHistoryResilient(coinId, days, deps = {}) {
  const primary = deps.primary ?? fetchDailyHistory;
  const secondary = deps.secondary ?? fetchDailyHistoryCoinbase;
  const products = deps.products ?? COINBASE_PRODUCTS;
  const chain = [];

  const cg = await primary(coinId, days);
  if (cg.ok) {
    chain.push({ source: 'coingecko-public', outcome: 'ok' });
    return { ...cg, dataset: { ...cg.dataset, sourceChain: chain } };
  }
  chain.push({ source: 'coingecko-public', outcome: 'unavailable', note: cg.unavailable?.note ?? 'unknown error' });

  const product = products[coinId];
  if (!product) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `${cg.unavailable?.note ?? 'coingecko failed'}; no Coinbase product mapping for '${coinId}' — fail closed`, sourceChain: chain } };
  }
  const cb = await secondary(product, days);
  if (cb.ok) {
    chain.push({ source: 'coinbase-exchange-public', outcome: 'ok' });
    return { ...cb, dataset: { ...cb.dataset, sourceChain: chain } };
  }
  chain.push({ source: 'coinbase-exchange-public', outcome: 'unavailable', note: cb.unavailable?.note ?? 'unknown error' });

  return {
    ok: false,
    unavailable: {
      label: 'UNAVAILABLE',
      note: `all sources failed — ${chain.map((c) => `${c.source}: ${c.note ?? c.outcome}`).join(' | ')}`,
      sourceChain: chain,
    },
  };
}
