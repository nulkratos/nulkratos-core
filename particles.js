(function(){
  const canvas=document.createElement('canvas');canvas.style.cssText='position:fixed;inset:0;pointer-events:none;z-index:0';document.body.prepend(canvas);
  const ctx=canvas.getContext('2d');let W,H;
  function resize(){W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;}
  window.addEventListener('resize',resize);resize();
  function Particle(){this.reset();}
  Particle.prototype.reset=function(){this.x=Math.random()*W;this.y=Math.random()*H;this.r=Math.random()*1.5+.2;this.vx=(Math.random()-.5)*.09;this.vy=-(Math.random()*.14+.03);this.life=Math.random();this.maxLife=Math.random()*.5+.28;const roll=Math.random();this.color=roll>.7?'#00f5ff':roll>.4?'#00c8d4':'#00ff87';};
  Particle.prototype.update=function(){this.x+=this.vx;this.y+=this.vy;this.life-=.0015;if(this.life<=0||this.y<-10)this.reset();};
  Particle.prototype.draw=function(){const alpha=Math.min(this.life/this.maxLife,1)*.4;ctx.save();ctx.globalAlpha=alpha;ctx.fillStyle=this.color;ctx.shadowBlur=7;ctx.shadowColor=this.color;ctx.beginPath();ctx.arc(this.x,this.y,this.r,0,Math.PI*2);ctx.fill();ctx.restore();};
  const particles=Array.from({length:60},()=>new Particle());
  function animate(){ctx.clearRect(0,0,W,H);particles.forEach(p=>{p.update();p.draw();});requestAnimationFrame(animate);}
  animate();
})();
