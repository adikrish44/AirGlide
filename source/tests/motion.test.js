import {test} from 'node:test';
import assert from 'node:assert/strict';
import {MotionEngine,angleDelta,pointingAngles} from '../web/motion.js';

test('heading wrap does not jump across 0/360',()=>{
 assert.equal(angleDelta(1,359),2);assert.equal(angleDelta(359,1),-2);
 const e=new MotionEngine();e.smoothing=false;e.sample(359,20,0,0);e.sample(1,20,0,16);
 assert.equal(e.take().dx,-52);
});
test('portrait pointing uses yaw and pitch, ignoring roll',()=>{
 const p=pointingAngles(35,25,0),q=pointingAngles(35,25,60);
 assert.ok(Math.abs(p.yaw-35)<1e-6);assert.ok(Math.abs(p.pitch-25)<1e-6);
 assert.ok(Math.abs(p.yaw-q.yaw)<1e-6);assert.ok(Math.abs(p.pitch-q.pitch)<1e-6);
});
test('reposition updates reference without moving or springing back',()=>{
 const e=new MotionEngine();e.smoothing=false;e.sample(0,20,0,0);
 e.sample(40,20,0,16,0,true);assert.deepEqual(e.take(),{dx:0,dy:0});
 e.sample(41,20,0,32);assert.deepEqual(e.take(),{dx:-26,dy:0});
});
test('reset and long sensor gaps do not move the pointer',()=>{
 const e=new MotionEngine();e.sample(0,0,0,0);e.sample(15,0,0,1000);assert.deepEqual(e.take(),{dx:0,dy:0});
 e.reset();e.sample(250,0,0,1100);assert.deepEqual(e.take(),{dx:0,dy:0});
});
test('invalid readings and ceiling-pointing do not move the cursor',()=>{
 const e=new MotionEngine();assert.equal(e.sample(null,0,0,0),false);
 assert.equal(pointingAngles(NaN,0,0),null);assert.equal(pointingAngles(15,90,0),null);
 assert.deepEqual(e.take(),{dx:0,dy:0});
});
test('speed and inverted axes change the intended directions',()=>{
 const e=new MotionEngine();e.smoothing=false;e.speed=2;e.invertX=e.invertY=true;
 e.sample(0,20,0,0);e.sample(1,21,0,16);assert.deepEqual(e.take(),{dx:52,dy:52});
});
test('sensor discontinuities are suppressed',()=>{
 const e=new MotionEngine();e.sample(0,0,0,0);e.sample(150,0,0,16);assert.deepEqual(e.take(),{dx:0,dy:0});
});
test('small hand jitter is suppressed',()=>{
 const e=new MotionEngine();e.sample(0,20,0,0);
 for(let i=1;i<20;i++)e.sample(i%2*.005,20+i%2*.005,0,i*16);
 assert.deepEqual(e.take(),{dx:0,dy:0});
});
test('landscape orientation preserves finite direction',()=>{
 const p=pointingAngles(30,15,10,90);assert.ok(Number.isFinite(p.yaw)&&Number.isFinite(p.pitch));
});
