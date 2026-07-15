/**
 * ingest/coingecko.mjs — historical daily closes from the CoinGecko PUBLIC
 * API (keyless). External feed ⇒ raw datapoints are REPORTED. A backtest
 * run over this real history is MEASURED (with the dataset hash pinned in
 * the receipt so the measurement is reproducible).
 *
 * Rate honesty: the public tier is IP-shared (~10-30 calls/min, dynamic).
 * We fetch serially with a fixed delay and fail CLOSED (UNAVAILABLE) on
 * any non-200 — never a silent fallback, never invented candles.
 */
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../canonical-json.mjs';

const BASE = 'https://api.coingecko.com/api/v3';

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'szl-quant/1.0 (advisory research; paper-only)' } });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    return { ok: false, status: res.status, note: body.slice(0, 200) };
  }
  return { ok: true, json: await res.json() };
}

/**
 * Fetch up to `days` of daily prices for a coin id (e.g. 'bitcoin').
 * Returns { ok, series?, dataset?, unavailable? } — fail closed on error.
 * series: [{ tMs, close }] daily. dataset: { source, url, sha256, n }.
 */
export async function fetchDailyHistory(coinId, days, vsCurrency = 'usd') {
  const url = `${BASE}/coins/${encodeURIComponent(coinId)}/market_chart?vs_currency=${vsCurrency}&days=${days}&interval=daily`;
  const r = await getJson(url);
  if (!r.ok) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coingecko ${coinId}: HTTP ${r.status ?? 'ERR'} ${r.note ?? ''}`.trim() } };
  }
  const prices = Array.isArray(r.json?.prices) ? r.json.prices : null;
  if (!prices || prices.length < 2) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coingecko ${coinId}: empty/short price array` } };
  }
  const series = prices
    .filter((p) => Array.isArray(p) && Number.isFinite(p[0]) && Number.isFinite(p[1]) && p[1] > 0)
    .map(([tMs, close]) => ({ tMs, close }));
  if (series.length < 2) {
    return { ok: false, unavailable: { label: 'UNAVAILABLE', note: `coingecko ${coinId}: no valid datapoints` } };
  }
  const sha256 = createHash('sha256').update(canonicalBytes(series)).digest('hex');
  return {
    ok: true,
    series,
    dataset: {
      source: 'coingecko-public',           // external feed
      sourceLabel: 'REPORTED',              // we did not verify the venue data
      coinId, vsCurrency, requestedDays: days,
      url, n: series.length,
      firstIso: new Date(series[0].tMs).toISOString(),
      lastIso: new Date(series[series.length - 1].tMs).toISOString(),
      sha256,                                // pins the exact bytes measured
    },
  };
}

export const RATE_DELAY_MS = 15000; // ~4/min — well under the shared public tier
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
