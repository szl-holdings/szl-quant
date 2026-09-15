import test from 'node:test';
import assert from 'node:assert/strict';
import { pointInTimeGate, researchBudgetGate } from '../src/gates.mjs';
const observation=()=>({contentSha256:'a'.repeat(64),eventAtMs:900,publishedAtMs:920,retrievedAtMs:950});

test('temporal gate accepts consistent declarations without authenticating them',()=>{
 const r=pointInTimeGate([observation()],1000,100);
 assert.equal(r.verdict,'ALLOWED');assert.equal(r.evidence.authenticationVerified,false);
});
for (const [label,mutate] of [
 ['future retrieval',r=>r.retrievedAtMs=1001],
 ['publication after retrieval',r=>r.publishedAtMs=960],
 ['event after publication',r=>r.eventAtMs=940],
 ['missing publication',r=>delete r.publishedAtMs],
 ['future event',r=>{r.eventAtMs=1001;r.publishedAtMs=1002;r.retrievedAtMs=1003;}],
 ['unknown provenance hash',r=>r.contentSha256='not-a-digest'],
 ['negative event',r=>r.eventAtMs=-1],
 ['numeric string',r=>r.eventAtMs='900'],
 ['nonfinite time',r=>r.eventAtMs=Infinity],
 ['stale event with fresh fetch',r=>{r.eventAtMs=899;r.retrievedAtMs=1000;}],
]) test(`point-in-time refuses ${label}`,()=>{
 const r=observation();mutate(r);assert.equal(pointInTimeGate([r],1000,100).verdict,'BLOCKED');
});
for(const [label,rows] of [['missing',null],['empty',[]],['duplicated',[observation(),observation()]],['sparse',Array(2)],['oversize',Array(513)]])
 test(`point-in-time refuses ${label} collection`,()=>assert.equal(pointInTimeGate(rows,1000,100).verdict,'BLOCKED'));

test('research budget includes outstanding reservations and next estimate',()=>{
 assert.equal(researchBudgetGate({budgetMicroUsd:100,spentMicroUsd:40,reservedMicroUsd:40,estimatedNextMicroUsd:21}).verdict,'BLOCKED');
 const r=researchBudgetGate({budgetMicroUsd:100,spentMicroUsd:40,reservedMicroUsd:40,estimatedNextMicroUsd:20});
 assert.equal(r.verdict,'ALLOWED');assert.equal(r.evidence.projectedRemainingMicroUsd,0);assert.equal(r.evidence.reservationPerformed,false);
});
for(const value of [undefined,NaN,-1,Infinity,0.1,'1',Number.MAX_SAFE_INTEGER+1])
 test(`budget refuses invalid estimate ${String(value)}`,()=>assert.equal(researchBudgetGate({budgetMicroUsd:100,spentMicroUsd:0,reservedMicroUsd:0,estimatedNextMicroUsd:value}).verdict,'BLOCKED'));
test('safe-integer inputs cannot overflow a summed budget check',()=>{
 const m=Number.MAX_SAFE_INTEGER;
 assert.equal(researchBudgetGate({budgetMicroUsd:m,spentMicroUsd:m-1,reservedMicroUsd:1,estimatedNextMicroUsd:1}).verdict,'BLOCKED');
});
test('pure budget checks do not mutate caller reservations',()=>{
 const x={budgetMicroUsd:100,spentMicroUsd:0,reservedMicroUsd:0,estimatedNextMicroUsd:10};const before=JSON.stringify(x);
 researchBudgetGate(x);assert.equal(JSON.stringify(x),before);
});

import { reviewResearchInputs } from '../src/engine.mjs';
const input=()=>({observations:[observation()],decisionAtMs:1000,maxEventAgeMs:100,
 researchBudget:{budgetMicroUsd:100,spentMicroUsd:0,reservedMicroUsd:0,estimatedNextMicroUsd:10}});
test('engine entry point only returns nonauthorizing research review',async()=>{
 const r=await reviewResearchInputs(input());
 assert.equal(r.disposition,'REVIEW');
 for (const k of ['evidenceAuthenticationVerified','budgetReservationPerformed','paperFillAuthorized','realMoneyExecutionAuthorized','ledgerMutationPerformed']) assert.equal(r[k],false);
});
test('engine entry point abstains on future evidence',async()=>{
 const x=input();x.observations[0].retrievedAtMs=1001;
 const r=await reviewResearchInputs(x);assert.equal(r.disposition,'ABSTAIN');assert.deepEqual(r.blockedBy,['point-in-time']);
});
test('engine entry point abstains on exhausted research budget',async()=>{
 const x=input();x.researchBudget.spentMicroUsd=100;
 assert.equal((await reviewResearchInputs(x)).disposition,'ABSTAIN');
});
test('missing research input does not authorize or throw',async()=>assert.equal((await reviewResearchInputs()).disposition,'ABSTAIN'));
