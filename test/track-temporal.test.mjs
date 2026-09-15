// SPDX-License-Identifier: Apache-2.0
// Synthetic, network-free tests. No order, wallet, account or ledger writes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreSignal, buildTrackRecord } from '../src/track.mjs';

const T = Date.parse('2026-01-01T00:00:00.000Z');
const DAY = 86400000;
const statement = (time=T) => ({subject:[{name:`szl-quant/signal/T/${new Date(time).toISOString()}`}],predicate:{decision:{asset:{symbol:'TEST',address:'TEST'},verdict:'ALLOWED',proposedAction:'ENTER_LONG'}}});
const history = Array.from({length:10},(_,i)=>({tMs:T+i*DAY,close:100+i}));
const run = (overrides={}) => scoreSignal({statement:statement(),series:history,source:'SYNTHETIC_FIXTURE',nowMs:T+9*DAY,horizons:[1,7],...overrides});

test('future supplied prices cannot settle an unelapsed horizon',()=>{
 const r=run({nowMs:T+DAY});
 assert.equal(r.outcomes.h1d.label,'MEASURED');
 assert.equal(r.outcomes.h7d.label,'UNAVAILABLE');
 assert.equal(r.outcomes.h7d.code,'HORIZON_PENDING');
 assert.equal('forwardReturn' in r.outcomes.h7d,false);
});
test('future price perturbations preserve every as-of output',()=>{
 const nowMs=T+2*DAY;
 const changed=history.map(c=>({...c,close:c.tMs>nowMs?999999:c.close}));
 assert.deepEqual(run({nowMs}),run({nowMs,series:changed}));
 assert.deepEqual(run({nowMs}),run({nowMs,series:history.filter(c=>c.tMs<=nowMs)}));
});
test('future signal cannot receive a historical outcome',()=>{
 const r=run({statement:statement(T+DAY),nowMs:T});
 assert.equal(r.outcomes.h1d.code,'FUTURE_SIGNAL');
});
for(const nowMs of [NaN,Infinity,-1,'1767225600000',undefined]) {
 test(`invalid as-of clock ${String(nowMs)} withholds measurement`,()=>{
  assert.equal(run({nowMs}).outcomes.h1d.code,'INVALID_AS_OF');
 });
}
for(const [name,series] of [
 ['duplicate',[history[0],history[0],history[1]]],
 ['unordered',[history[1],history[0]]],
 ['negative',[{tMs:T,close:-1}]],
 ['string price',[{tMs:T,close:'100'}]],
 ['infinite price',[{tMs:T,close:Infinity}]],
 ['fractional timestamp',[{tMs:T+0.5,close:100}]],
 ['nonarray',{}],
]) {
 test(`invalid history ${name} cannot be scored`,()=>{
  assert.equal(run({series}).outcomes.h1d.code,'INVALID_HISTORY');
 });
}
test('distant closes cannot substitute for a missing baseline',()=>{
 const r=run({series:history.slice(2)});
 assert.equal(r.outcomes.h1d.code,'BASELINE_GAP');
 assert.equal(r.outcomes.h7d.code,'BASELINE_GAP');
});
test('a close outside the requested daily horizon stays a gap',()=>{
 const r=run({series:[history[0],history[9]]});
 assert.equal(r.outcomes.h7d.code,'OUTCOME_GAP');
});
test('exact as-of boundary is observable and carries actual interval',()=>{
 const r=run({nowMs:T+7*DAY});
 assert.equal(r.outcomes.h7d.label,'MEASURED');
 assert.equal(r.outcomes.h7d.realizedIntervalMs,7*DAY);
 assert.equal(r.outcomes.h7d.evaluatedAsOfIso,new Date(T+7*DAY).toISOString());
 assert.equal(r.outcomes.h7d.horizonAnchor,'decision-clock');
});
test('finite inputs with an overflowing ratio do not generate infinite performance',()=>{
 const r=run({series:[{tMs:T,close:Number.MIN_VALUE},{tMs:T+DAY,close:Number.MAX_VALUE}],horizons:[1]});
 assert.equal(r.outcomes.h1d.code,'NONFINITE_RETURN');
});
test('invalid or duplicate horizon configuration is rejected',()=>{
 for(const horizons of [[],[0],[-1],[0.5],[7,7],['7'],[3651]]) {
  assert.throws(()=>run({horizons}),/horizons/);
 }
});
test('missing signal clock cannot be measured',()=>{
 assert.equal(run({statement:{}}).outcomes.h1d.code,'INVALID_SIGNAL_TIME');
});
test('empty future-outcome evidence remains null at aggregate level',()=>{
 const rep=buildTrackRecord({verified:[{file:'fixture',statement:statement()}],excluded:[],histories:{TEST:{ok:true,series:history,dataset:{source:'SYNTHETIC_FIXTURE',sha256:'0'.repeat(64)}}},nowMs:T+DAY,horizons:[7]});
 assert.equal(rep.aggregates.h7d.nRealized,0);
 assert.equal(rep.aggregates.h7d.nPending,1);
 assert.equal(rep.aggregates.h7d.hitRate,null);
 assert.equal(rep.aggregates.h7d.meanForwardReturn,null);
});

test('malformed subject name degrades rather than throwing',()=>{
 assert.equal(run({statement:{subject:[{name:123}]}}).outcomes.h1d.code,'INVALID_SIGNAL_TIME');
});
test('empty track discloses missing evidence instead of operational approval',()=>{
 const r=buildTrackRecord({verified:[],excluded:[],histories:{},nowMs:T,horizons:[1,7]});
 assert.equal(r.researchQualification.evidenceState,'NO_VERIFIED_SIGNALS');
 assert.equal(r.researchQualification.state,'HOLD');
 assert.equal(r.researchQualification.capitalAdmission,false);
 assert.equal(r.researchQualification.liveExecution,false);
});
test('even positive measured fixture outcomes never admit capital',()=>{
 const r=buildTrackRecord({verified:[{file:'fixture',statement:statement()}],excluded:[],histories:{TEST:{ok:true,series:history,dataset:{source:'SYNTHETIC_FIXTURE'}}},nowMs:T+9*DAY,horizons:[1,7]});
 assert.equal(r.researchQualification.evidenceState,'DESCRIPTIVE_OUTCOMES_ONLY');
 assert.equal(r.researchQualification.horizonCounts.h1d.realized,1);
 assert.equal(r.researchQualification.horizonCounts.h7d.realized,1);
 assert.equal(r.researchQualification.capitalAdmission,false);
 assert.equal(r.researchQualification.outOfSampleSkillEstablished,false);
});
