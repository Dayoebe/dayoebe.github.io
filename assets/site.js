const menuButton=document.querySelector('[data-menu]');const menu=document.querySelector('[data-nav]');if(menuButton&&menu){menuButton.addEventListener('click',()=>{const open=menu.classList.toggle('open');menuButton.setAttribute('aria-expanded',String(open))});menu.addEventListener('click',e=>{if(e.target.closest('a')){menu.classList.remove('open');menuButton.setAttribute('aria-expanded','false')}})}
const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;const items=document.querySelectorAll('[data-reveal]');if(!reduced&&'IntersectionObserver'in window){const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}}),{threshold:.12});items.forEach(item=>observer.observe(item))}else{items.forEach(item=>item.classList.add('visible'))}
document.querySelectorAll('[data-year]').forEach(el=>el.textContent=new Date().getFullYear());
if(location.protocol==='http:'||location.protocol==='https:'){
  const siteScript=[...document.scripts].find(script=>script.src.endsWith('/assets/site.js'));
  const siteRoot=siteScript?new URL('../',siteScript.src):new URL('./',location.href);
  const manifest=document.createElement('link');
  manifest.rel='manifest';
  manifest.href=new URL('manifest.webmanifest',siteRoot).href;
  document.head.append(manifest);
  if('serviceWorker'in navigator){addEventListener('load',()=>navigator.serviceWorker.register(new URL('service-worker.js',siteRoot)).catch(()=>{}))}
}
