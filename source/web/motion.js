// Relative pointing with a top-edge direction vector. Sensor data stays local.
export function angleDelta(a,b){return ((a-b+540)%360+360)%360-180;}
export function pointingAngles(alpha,beta,gamma,screenAngle=0){
  if (![alpha,beta,gamma,screenAngle].every(Number.isFinite)) return null;
  const r=Math.PI/180,a=alpha*r,b=beta*r,g=gamma*r,s=screenAngle*r;
  const ca=Math.cos(a),sa=Math.sin(a),cb=Math.cos(b),sb=Math.sin(b),cg=Math.cos(g),sg=Math.sin(g);
  const vx=Math.sin(s),vy=Math.cos(s);
  // W3C intrinsic Z-X'-Y'' rotation applied to the screen's top-edge vector.
  const x=(ca*cg-sa*sb*sg)*vx-sa*cb*vy;
  const y=(sa*cg+ca*sb*sg)*vx+ca*cb*vy;
  const z=-cb*sg*vx+sb*vy;
  const horizontal=Math.hypot(x,y);
  if(horizontal<0.16)return null; // Avoid undefined yaw when pointed at the ceiling.
  return {yaw:Math.atan2(-x,y)/r,pitch:Math.atan2(z,horizontal)/r};
}
export class MotionEngine{
  constructor(){this.speed=1;this.smoothing=true;this.invertX=false;this.invertY=false;this.reset();}
  reset(){this.previous=null;this.vx=0;this.vy=0;this.pendingX=0;this.pendingY=0;}
  sample(alpha,beta,gamma,time,screenAngle=0,paused=false){
    const point=pointingAngles(alpha,beta,gamma,screenAngle);
    if(!point){this.reset();return false;}
    const last=this.previous;this.previous={...point,time};
    if(paused||!last){this.vx=this.vy=this.pendingX=this.pendingY=0;return true;}
    const dt=(time-last.time)/1000;
    const dx=-angleDelta(point.yaw,last.yaw),dy=-(point.pitch-last.pitch);
    if(dt<0.003||dt>0.16||Math.abs(dx)>30||Math.abs(dy)>30){this.vx=this.vy=0;return true;}
    const dead=this.smoothing?0.025:0.008;
    const x=Math.abs(dx)<dead?0:dx,y=Math.abs(dy)<dead?0:dy;
    const blend=this.smoothing?1-Math.exp(-dt/0.022):1;
    this.vx+=(x/dt-this.vx)*blend;this.vy+=(y/dt-this.vy)*blend;
    this.pendingX+=this.vx*dt*26*this.speed*(this.invertX?-1:1);
    this.pendingY+=this.vy*dt*26*this.speed*(this.invertY?-1:1);
    return true;
  }
  take(){
    const dx=Math.round(Math.max(-450,Math.min(450,this.pendingX)));
    const dy=Math.round(Math.max(-450,Math.min(450,this.pendingY)));
    this.pendingX=Math.max(-450,Math.min(450,this.pendingX))-dx;
    this.pendingY=Math.max(-450,Math.min(450,this.pendingY))-dy;
    return {dx,dy};
  }
}
