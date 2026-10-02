// SPDX-License-Identifier: Apache-2.0
// New callers use the corrected generation-8 contract. Historical replay is explicitly separate.
export { replaySeriesV8 as replaySeries, walkForwardV8 as walkForward } from './backtest-v8.mjs';
