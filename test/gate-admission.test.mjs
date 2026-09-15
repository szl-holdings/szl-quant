/** Regression tests: malformed controls cannot silently produce ALLOWED. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { runGates, postureGate, freshnessGate, sampleSizeGate, liquidityGate,
  volatilityGate, convictionGate } from '../src/gates.mjs';

const allowed = () => ({gate:'example',verdict:'ALLOWED',reason:'fixture'});
for (const [name,value] of [
  ['empty',[]], ['missing',undefined], ['null',null], ['object',{}],
  ['null result',[null]], ['unknown result',[{gate:'example',verdict:'UNKNOWN',reason:'fixture'}]],
  ['missing verdict',[{gate:'example',reason:'fixture'}]],
  ['empty gate',[{gate:'',verdict:'ALLOWED',reason:'fixture'}]],
  ['empty reason',[{gate:'example',verdict:'ALLOWED',reason:''}]],
  ['duplicate gate',[allowed(),allowed()]],
  ['sparse array',Array(2)]
]) test(`aggregate refuses ${name}`,()=>assert.equal(runGates(value).verdict,'BLOCKED'));

test('valid gate values and reasons are not rewritten',()=>{
 const gates=[postureGate(),allowed()];const original=JSON.stringify(gates);
 const out=runGates(gates);
 assert.equal(out.verdict,'ALLOWED');assert.deepEqual(out.gates,gates);
 assert.equal(JSON.stringify(gates),original);
});
test('existing explicit refusal is preserved',()=>{
 const refusal={gate:'liquidity',verdict:'BLOCKED',reason:'insufficient fixture liquidity'};
 const out=runGates([postureGate(),refusal]);
 assert.equal(out.verdict,'BLOCKED');assert.deepEqual(out.blockedBy,['liquidity']);
 assert.deepEqual(out.gates[1],refusal);
});
for(const limit of [undefined,null,NaN,Infinity,-1,'100'])
 test(`invalid freshness limit ${String(limit)}`,()=>assert.equal(freshnessGate(900,1000,limit).verdict,'BLOCKED'));
for(const minimum of [undefined,null,NaN,Infinity,0,-1,1.5])
 test(`invalid observation floor ${String(minimum)}`,()=>assert.equal(sampleSizeGate(100,minimum).verdict,'BLOCKED'));
for(const minimum of [undefined,null,NaN,Infinity,-1,'1'])
 test(`invalid liquidity floor ${String(minimum)}`,()=>assert.equal(liquidityGate(100,100,minimum,0).verdict,'BLOCKED'));
for(const cap of [undefined,null,NaN,Infinity,-1])
 test(`invalid volatility cap ${String(cap)}`,()=>assert.equal(volatilityGate(0.1,cap).verdict,'BLOCKED'));
for(const floor of [undefined,null,NaN,Infinity,-1,0.98])
 test(`invalid conviction floor ${String(floor)}`,()=>assert.equal(convictionGate(0.6,floor).verdict,'BLOCKED'));
test('negative observation and volatility domains refused',()=>{
 assert.equal(sampleSizeGate(-1,1).verdict,'BLOCKED');
 assert.equal(sampleSizeGate(1.5,1).verdict,'BLOCKED');
 assert.equal(volatilityGate(-.1,1).verdict,'BLOCKED');
 assert.equal(freshnessGate(-1,1000,2000).verdict,'BLOCKED');
});
test('valid boundary controls stay exact',()=>{
 assert.equal(freshnessGate(1000,1000,0).verdict,'ALLOWED');
 assert.equal(sampleSizeGate(45,45).verdict,'ALLOWED');
 assert.equal(liquidityGate(0,0,0,0).verdict,'ALLOWED');
 assert.equal(volatilityGate(0,0).verdict,'ALLOWED');
 assert.equal(convictionGate(0,0).verdict,'ALLOWED');
});
