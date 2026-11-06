import {MotionEngine} from './motion.js';

const $=id=>document.getElementById(id);
const preview=new URLSearchParams(location.search).get('demo')==='1';
const engine=new MotionEngine();
let ws=null,connected=false,motionOn=false,mode='air',holding=false,freezeUntil=0;
let heartbeat=null,retryTimer=null,retries=0,manualStop=false,lastPong=0,wakeLock=null;
let lastSensor=0,sensorCheck=null,toastTimer=null,clickTimer=null;
const safeStore={get(k){try{return localStorage.getItem(k);}catch{return null;}},set(k,v){try{localStorage.setItem(k,v);}catch{}}};

function toast(message){
  const target=document.querySelector('dialog[open]')||document.body;
  target.appendChild($('toast'));
  $('toast').textContent=message;$('toast').classList.add('show');
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.remove('show'),3500);
}
function status(text,live=false){
  $('status-label').textContent=text;$('connection').classList.toggle('live',live);
}
function dialogOpen(){return Boolean(document.querySelector('dialog[open]'));}
function isMotionPaused(){return !connected||!motionOn||mode!=='air'||holding||dialogOpen()||document.hidden||performance.now()<freezeUntil;}
function send(command,quiet=false){
  if(preview){if(!quiet&&command.type!=='move')toast('Preview only · Connect the Windows companion to control your PC.');return true;}
  if(!connected||!ws||ws.readyState!==WebSocket.OPEN){if(!quiet)toast('Connect to your PC first.');return false;}
  if(command.type==='move'&&ws.bufferedAmount>16384)return false; // Discard stale motion, never queue it.
  if(ws.bufferedAmount>65536){ws.close();return false;}
  ws.send(JSON.stringify(command));return true;
}
function motionUI(){
  const active=motionOn&&mode==='air';
  $('motion-start').hidden=mode!=='air'||active;
  $('left-click').hidden=mode==='touch';
  $('touch-hint').hidden=mode!=='touch';
  $('motion-dot').classList.toggle('active',active&&!holding);
  $('motion-caption').textContent=mode==='touch'?'Move, tap, or scroll with two fingers':holding?'Repositioning · pointer paused':active?'Move your wrist to move the pointer':'Ready when you are';
  $('pause-motion').textContent=motionOn?'Pause motion':'Enable motion';
  $('reposition').disabled=mode==='touch';
}
function stopMotion(message){
  motionOn=false;holding=false;engine.reset();$('reposition').classList.remove('holding');
  clearTimeout(sensorCheck);motionUI();if(message)toast(message);
  if(wakeLock){wakeLock.release().catch(()=>{});wakeLock=null;}
}
async function keepAwake(){
  try{if('wakeLock' in navigator&&!document.hidden){wakeLock=await navigator.wakeLock.request('screen');wakeLock.addEventListener('release',()=>{wakeLock=null;});}}catch{}
}
function useTouchpad(message){
  stopMotion();
  chooseMode('touch');
  toast(message);
}
async function enableMotion(){
  if(!connected){toast('Connect to your PC first.');return;}
  if(preview){motionOn=true;engine.reset();motionUI();return;}
  if(!window.isSecureContext){toast('Open the HTTPS remote link after completing certificate setup.');return;}
  if(!('DeviceOrientationEvent' in window)){useTouchpad('Touchpad enabled. This browser does not provide motion sensors.');return;}
  try{
    // Must be called directly from a user gesture on iOS.
    const granted=typeof DeviceOrientationEvent.requestPermission==='function'?await DeviceOrientationEvent.requestPermission(): 'granted';
    if(granted!=='granted'){useTouchpad('Touchpad enabled. Allow motion access in your browser settings to try air mouse again.');return;}
    motionOn=true;lastSensor=0;engine.reset();motionUI();keepAwake();
    clearTimeout(sensorCheck);
    sensorCheck=setTimeout(()=>{
      if(motionOn&&mode==='air'&&!lastSensor)useTouchpad('No motion readings. Use the touchpad, or allow motion sensors in your browser settings and try Air mouse again.');
    },3000);
  }catch{useTouchpad('Touchpad enabled. To retry motion, open the secure link in Chrome on Android or Safari on iPhone.');}
}
window.addEventListener('deviceorientation',event=>{
  if(!motionOn)return;
  if(![event.alpha,event.beta,event.gamma].every(Number.isFinite))return;
  lastSensor=performance.now();
  const angle=screen.orientation?.angle??(typeof window.orientation==='number'?window.orientation:0);
  const valid=engine.sample(event.alpha,event.beta,event.gamma,lastSensor,angle,isMotionPaused());
  if(!valid)$('motion-caption').textContent='Lower the phone · aim its top edge at the screen';
  else if(!holding)$('motion-caption').textContent='Move your wrist to move the pointer';
});
function frame(){
  if(!isMotionPaused()){const move=engine.take();if(move.dx||move.dy)send({type:'move',...move},true);}
  else{engine.pendingX=engine.pendingY=0;}
  requestAnimationFrame(frame);
}
requestAnimationFrame(frame);
window.addEventListener('orientationchange',()=>engine.reset());

function showRemote(name,realInput=true){
  $('pairing').hidden=true;$('remote').hidden=false;
  $('device-name').textContent=name||'Your Windows PC';
  if(!realInput&&!preview){$('preview-banner').textContent='SIMULATOR · NO WINDOWS INPUT';$('preview-banner').hidden=false;}
}
function showPairing(message=''){
  connected=false;stopMotion();$('pairing').hidden=false;$('remote').hidden=true;
  $('pair-error').textContent=message;status('Offline');$('latency').textContent='— ms';
}
async function checkSession(){
  try{
    const r=await fetch('/api/session',{cache:'no-store'});
    if(r.status===401){showPairing();return false;}
    if(!r.ok)throw new Error();
    const d=await r.json();showRemote(d.name,d.realInput);startSocket();return true;
  }catch{
    status('Offline');$('connection-help').hidden=$('remote').hidden;
    if(!$('remote').hidden&&!manualStop&&!document.hidden){
      clearTimeout(retryTimer);
      retryTimer=setTimeout(()=>checkSession(),Math.min(1000*2**retries++,10000));
    }
    return false;
  }
}
function startSocket(){
  if(preview||document.hidden||manualStop)return;
  clearTimeout(retryTimer);
  if(ws){ws.onclose=null;ws.close();}
  connected=false;status('Connecting');
  const socket=new WebSocket('wss://'+location.host+'/ws');ws=socket;
  const timer=setTimeout(()=>{if(socket.readyState!==WebSocket.OPEN)socket.close();},8000);
  socket.onmessage=event=>{
    if(ws!==socket)return;
    let message;try{message=JSON.parse(event.data);}catch{return;}
    if(message.type==='hello'){
      clearTimeout(timer);connected=true;retries=0;lastPong=Date.now();status(message.realInput?'Connected':'Simulator',true);
      showRemote(message.name,message.realInput);$('connection-help').hidden=true;
      clearInterval(heartbeat);
      const ping=()=>{if(Date.now()-lastPong>12000){socket.close();return;}send({type:'ping',id:Date.now()},true);};
      heartbeat=setInterval(ping,4000);ping();
    }else if(message.type==='pong'){
      lastPong=Date.now();$('latency').textContent=Math.max(0,Date.now()-message.id)+' ms';
    }else if(message.type==='error'){toast(message.message);}
    else if(message.type==='expired'){manualStop=true;socket.close();showPairing('Pair again using the current code on your PC.');}
  };
  socket.onclose=event=>{
    clearTimeout(timer);if(ws!==socket)return;
    connected=false;clearInterval(heartbeat);stopMotion();status('Offline');$('latency').textContent='— ms';
    $('connection-help').hidden=$('remote').hidden;
    if(event.code===4001){manualStop=true;toast('Another remote took control. Tap Reconnect to use this phone.');return;}
    if(!manualStop&&!document.hidden){retryTimer=setTimeout(()=>checkSession(),Math.min(1000*2**retries++,10000));}
  };
  socket.onerror=()=>{status('Offline');};
}
$('pair-form').addEventListener('submit',async event=>{
  event.preventDefault();const pin=$('pin').value.trim();if(!/^\d{6}$/.test(pin)){return;}
  $('pair-button').disabled=true;$('pair-error').textContent='';
  try{
    const r=await fetch('/api/pair',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error||'Pairing failed.');
    manualStop=false;showRemote(data.name,data.realInput);$('pin').value='';startSocket();
  }catch(error){$('pair-error').textContent=error instanceof TypeError?'Cannot reach the PC. Keep its companion running on the same Wi-Fi.':error.message;}
  finally{$('pair-button').disabled=false;}
});
$('pin').addEventListener('input',()=>$('pin').value=$('pin').value.replace(/\D/g,''));

$('enable-motion').addEventListener('click',enableMotion);
function chooseMode(next){
  mode=next;engine.reset();holding=false;
  for(const m of ['air','touch']){$('mode-'+m).classList.toggle('selected',m===mode);$('mode-'+m).setAttribute('aria-pressed',String(m===mode));}
  motionUI();if(next==='touch')keepAwake();
}
$('mode-air').onclick=()=>chooseMode('air');$('mode-touch').onclick=()=>chooseMode('touch');
function flashClick(){
  $('left-click').classList.add('clicked');clearTimeout(clickTimer);clickTimer=setTimeout(()=>$('left-click').classList.remove('clicked'),150);
}
$('left-click').addEventListener('click',()=>{if(send({type:'click',button:'left'}))flashClick();});
$('right-click').addEventListener('click',()=>send({type:'click',button:'right'}));
document.addEventListener('pointerdown',()=>{freezeUntil=performance.now()+100;},true);
document.addEventListener('pointerup',()=>{freezeUntil=performance.now()+100;},true);
function releaseGrip(){holding=false;$('reposition').classList.remove('holding');engine.reset();motionUI();}
$('reposition').addEventListener('pointerdown',event=>{
  if(mode!=='air')return;event.preventDefault();$('reposition').setPointerCapture(event.pointerId);holding=true;engine.reset();$('reposition').classList.add('holding');motionUI();
});
for(const event of ['pointerup','pointercancel','lostpointercapture'])$('reposition').addEventListener(event,releaseGrip);
$('reposition').addEventListener('keydown',event=>{if(event.code==='Space'){event.preventDefault();holding=true;engine.reset();motionUI();}});
$('reposition').addEventListener('keyup',releaseGrip);

const touches=new Map();let touchStart=0,touchTravel=0,multiTouch=false,touchX=0,touchY=0,scrollRemainder=0;
function centroid(){const p=[...touches.values()];return {x:p.reduce((v,t)=>v+t.x,0)/p.length,y:p.reduce((v,t)=>v+t.y,0)/p.length};}
function scrollPixels(pixels){
  scrollRemainder+=pixels*4;const amount=Math.trunc(scrollRemainder);scrollRemainder-=amount;
  if(amount)send({type:'scroll',amount:Math.max(-1200,Math.min(1200,amount))},true);
}
$('pointer-surface').addEventListener('pointerdown',event=>{
  if(mode!=='touch')return;event.preventDefault();$('pointer-surface').setPointerCapture(event.pointerId);
  if(!touches.size){touchStart=performance.now();touchTravel=0;multiTouch=false;}
  touches.set(event.pointerId,{x:event.clientX,y:event.clientY});if(touches.size>1)multiTouch=true;
  const c=centroid();touchX=c.x;touchY=c.y;$('pointer-surface').classList.add('touched');
});
$('pointer-surface').addEventListener('pointermove',event=>{
  if(mode!=='touch'||!touches.has(event.pointerId))return;
  touches.set(event.pointerId,{x:event.clientX,y:event.clientY});
  const c=centroid(),dx=c.x-touchX,dy=c.y-touchY;touchX=c.x;touchY=c.y;touchTravel+=Math.hypot(dx,dy);
  if(touches.size>=2)scrollPixels(-dy);
  else if(!multiTouch)send({type:'move',dx:dx*1.65*engine.speed,dy:dy*1.65*engine.speed},true);
});
function endTouch(event){
  if(!touches.has(event.pointerId))return;touches.delete(event.pointerId);
  if(!touches.size){
    $('pointer-surface').classList.remove('touched');
    if(event.type==='pointerup'&&!multiTouch&&touchTravel<7&&performance.now()-touchStart<350)send({type:'click',button:'left'});
  }else{const c=centroid();touchX=c.x;touchY=c.y;}
}
for(const event of ['pointerup','pointercancel','lostpointercapture'])$('pointer-surface').addEventListener(event,endTouch);
let railY=null;
$('scroll-rail').addEventListener('pointerdown',event=>{event.preventDefault();$('scroll-rail').setPointerCapture(event.pointerId);railY=event.clientY;holding=true;engine.reset();});
$('scroll-rail').addEventListener('pointermove',event=>{if(railY===null)return;scrollPixels(railY-event.clientY);railY=event.clientY;});
for(const event of ['pointerup','pointercancel','lostpointercapture'])$('scroll-rail').addEventListener(event,()=>{railY=null;releaseGrip();});
$('scroll-rail').addEventListener('keydown',event=>{if(['ArrowUp','ArrowDown'].includes(event.key)){event.preventDefault();send({type:'scroll',amount:event.key==='ArrowUp'?120:-120});}});

document.querySelectorAll('[data-key]').forEach(button=>button.addEventListener('click',()=>send({type:'key',key:button.dataset.key})));
function openSheet(id){engine.reset();$(id).showModal();}
$('open-keyboard').onclick=()=>openSheet('keyboard-dialog');
$('open-settings').onclick=()=>openSheet('settings-dialog');
document.querySelectorAll('.close-sheet').forEach(button=>button.onclick=()=>button.closest('dialog').close());
document.querySelectorAll('dialog').forEach(dialog=>{
  dialog.addEventListener('close',()=>{engine.reset();freezeUntil=performance.now()+150;if(dialog.contains($('toast')))document.body.appendChild($('toast'));});
  dialog.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect();if(event.clientY<r.top||event.clientY>r.bottom||event.clientX<r.left||event.clientX>r.right)dialog.close();}});
});
$('send-text').onclick=()=>{const value=$('text-input').value;if(value&&send({type:'text',text:value})){$('text-input').value='';if(!preview)toast('Text sent to the active PC window.');}};
function applySettings(){
  engine.speed=Number($('sensitivity').value);engine.smoothing=$('smoothing').checked;
  engine.invertX=$('invert-x').checked;engine.invertY=$('invert-y').checked;
  $('sensitivity-value').textContent=engine.speed.toFixed(2).replace(/0$/,'')+'×';
  safeStore.set('airremote-settings',JSON.stringify({speed:engine.speed,smoothing:engine.smoothing,invertX:engine.invertX,invertY:engine.invertY}));engine.reset();
}
try{
  const settings=JSON.parse(safeStore.get('airremote-settings')||'{}');
  if(Number.isFinite(settings.speed))$('sensitivity').value=Math.max(.35,Math.min(2.5,settings.speed));
  for(const [id,key] of [['smoothing','smoothing'],['invert-x','invertX'],['invert-y','invertY']])if(typeof settings[key]==='boolean')$(id).checked=settings[key];
}catch{}
applySettings();
for(const id of ['sensitivity','smoothing','invert-x','invert-y'])$(id).addEventListener('input',applySettings);
$('pause-motion').onclick=()=>{if(motionOn)stopMotion();else{enableMotion();$('settings-dialog').close();}};
$('disconnect').onclick=async()=>{
  manualStop=true;clearTimeout(retryTimer);clearInterval(heartbeat);stopMotion();
  if(ws){ws.close();ws=null;}
  if(!preview)try{await fetch('/api/logout',{method:'POST'});}catch{}
  $('settings-dialog').close();showPairing('Disconnected. Enter the code to reconnect.');
};
async function reconnect(){manualStop=false;clearTimeout(retryTimer);if(preview){connected=true;showRemote('Windows PC');status('Preview');return;}if(!await checkSession())toast('Could not reconnect. Open the current QR link on your PC.');}
$('reconnect').onclick=reconnect;
$('connection').onclick=()=>{if(!connected)reconnect();else toast(preview?'Preview only · no PC connected.':'Connected to '+$('device-name').textContent+' over your local network.');};
document.addEventListener('visibilitychange',()=>{
  if(document.hidden){stopMotion();clearTimeout(retryTimer);clearInterval(heartbeat);if(ws){ws.onclose=null;ws.close();ws=null;}connected=false;status('Paused');}
  else if(!manualStop){if(preview){connected=true;status('Preview');}else checkSession();}
});
window.addEventListener('offline',()=>{connected=false;stopMotion();status('Offline');if(ws)ws.close();});
window.addEventListener('online',()=>{if(!manualStop&&!preview)checkSession();});
window.addEventListener('blur',()=>{holding=false;engine.reset();});

if(preview){connected=true;$('preview-banner').hidden=false;showRemote('Your Windows PC');status('Preview');$('latency').textContent='LOCAL';}
else checkSession();
motionUI();
if('serviceWorker' in navigator&&!preview&&window.isSecureContext){navigator.serviceWorker.register('/sw.js').catch(()=>{});}
