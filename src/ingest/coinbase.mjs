/**
 * ingest/coinbase.mjs — historical daily closes from the Coinbase Exchange
 * PUBLIC candles API (keyless). Same contract and honesty rules as the
 * CoinGecko module: external feed ⇒ raw datapoints are REPORTED; any
 * error ⇒ fail CLOSED (UNAVAILABLE); nothing is ever invented.
 *
 * Chosen over Binance for the fallback role after a MEASURED rejection:
 * api.binance.com returns HTTP 451 (geo-restricted) from US egress, and
 * both this engine's runners and GitHub-hosted runners are US-based — a
 * fallback that cannot fire is not resilience. Coinbase Exchange candles
 * are US-accessible and genuinely USD-quoted (no stablecoin-peg caveat).
 *
 * Rate honesty: public endpoints allow ~10 req/s per IP; a 365d backtest
 * needs 2 windowed calls per asset (300 daily buckets max per request).
 * We fetch serially with a fixed delay and never retry into a ban.
 */
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../canonical-json.mjs';

const BASE = 'https://api.exchange.coinbase.com';
const DAY_MS = 86_400_000;
const MAX_BUCKETS = 300; // API cap per candles request

/**
 * Parse raw candle rows into an ascending daily close series, keeping ONLY
 * closed candles (bucket start + 1d must be ≤ `nowMs`). Exported for unit
 * tests. Row shape per Coinbase Exchange docs (newest-first):
 * [ time(sec, bucket start), low, high, open, close, volume ].
 */
export function parseCandles(rows, nowMs) {
  if (!Array.isArray(rows)) return [];
  const byT = new Map();
  for (const r of rows) {
    if (!Array.isArray(r) || !Number.isFinite(r[0])) continue;
    const close = Number(r[4]);
    if (!Number.isFinite(close) || close <= 0) continue;
    const tMs = r[0] * 1000;
    if (tMs + DAY_MS > nowMs) continue; // candle still forming — not a fact yet
    byT.set(tMs, close);                // dedupe on bucket start
  }
  return [...byT.entries()].sort((a, b) => a[0] - b[0]).map(([tMs, close]) => ({ tMs, close }));
}

/**
 * Fetch up to `days` daily closes for a product (e.g. 'BTC-USD'), paging
 * in ≤300-bucket windows. Returns { ok, series?, dataset?, unavailable? }
 * — identical contract to coingecko.fetchDailyHistory, so callers can
 * fall back transparently while receipts still pin which source served.
 */
export async function fetchDailyHistoryCoinbase(productId, days) {
  const wanted = Math.min(Math.max(Math.trunc(days), 2), 3000);
  const endMs = Math.floor(Date.now() / DAY_MS) * DAY_MS; // today 00:00 UTC
  const rows = [];
  const urls = [];
  for (let got = 0; got < wanted; got += MAX_BUCKETS) {
    const winEnd = endMs - got * DAY_MS;
    const winStart = Math.max(winEnd - MAX_BUCKETS * DAY_MS, endMs - wanted * DAY_MS);
    const url = `${BASE}/products/${encodeURIComponent(productId)}/candles?granularity=86400&start=${new Date(winStart).toISOString()}&end=${new Date(winEnd).toISOString()}`;
    urls.push(url);
    let res;
    try {
      res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'szl-quant/1.0 (advisory research; paper-only)' } });
    } catch (e) {
      return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coinbase ${productId}: fetch error ${String(e?.message ?? e).slice(0, 120)}` } };
    }
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coinbase ${productId}: HTTP ${res.status} ${body.slice(0, 200)}`.trim() } };
    }
    const page = await res.json().catch(() => null);
    if (!Array.isArray(page)) {
      return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coinbase ${productId}: non-array response` } };
    }
    rows.push(...page);
    if (winStart <= endMs - wanted * DAY_MS) break;
    await new Promise((r) => setTimeout(r, 350)); // rate-honest between windows
  }
  const series = parseCandles(rows, Date.now());
  if (series.length < 2) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coinbase ${productId}: no valid closed candles` } };
  }
  const sha256 = createHash('sha256').update(canonicalBytes(series)).digest('hex');
  return {
    ok: true,
    series,
    dataset: {
      source: 'coinbase-exchange-public',     // external feed
      sourceLabel: 'REPORTED',                // we did not verify the venue data
      productId,
      vsCurrency: 'USD',
      requestedDays: days,
      url: urls[0], nWindows: urls.length, n: series.length,
      firstIso: new Date(series[0].tMs).toISOString(),
      lastIso: new Date(series[series.length - 1].tMs).toISOString(),
      sha256,                                  // pins the exact bytes measured
    },
  };
}
