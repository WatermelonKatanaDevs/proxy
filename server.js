import express from "express";
import { createServer } from "node:http";
import { WebSocket, WebSocketServer } from "ws";

const app = express(), server = createServer(app), wss = new WebSocketServer({ noServer: true });
const PORT = Number(process.env.PORT || 3000);
const CORSFIX = "https://proxy.corsfix.com/?";
const RETRY = new Set([403,408,419,429,500,502,503,504]);
const ISOLATION = "/isolation/", ASSET_ORIGIN = "https://assets.opendaw.studio";
const TTL = 86400, sessions = new Map();
const cors = {
  "Access-Control-Allow-Origin":"*", "Access-Control-Allow-Methods":"GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
  "Access-Control-Allow-Headers":"*", "Access-Control-Expose-Headers":"*", "Access-Control-Max-Age":"86400"
};
function corsOut(res) { for (const [k,v] of Object.entries(cors)) res.setHeader(k,v); }
function text(res,status,message) { corsOut(res); return res.status(status).type("text/plain").send(message); }
function json(res,status,data) { corsOut(res); res.setHeader("Content-Type","application/json; charset=utf-8"); res.setHeader("Cache-Control","no-store"); return res.status(status).send(JSON.stringify(data)); }
function validateId(id) { return /^[A-Za-z0-9_-]{1,128}$/.test(String(id||"")); }
function validateTarget(u,proxyOrigin) {
  if (!["http:","https:"].includes(u.protocol)) throw Error("Only HTTP and HTTPS URLs can be isolated.");
  if (u.username||u.password) throw Error("URLs containing credentials are not allowed.");
  if (u.origin===proxyOrigin) throw Error("The isolation proxy cannot proxy itself.");
  const h=u.hostname.toLowerCase().replace(/^\[|\]$/g,"");
  if (!h.includes(".")&&!h.includes(":")) throw Error("Single-label and local network hosts are not allowed.");
  if (h==="localhost"||/\.(localhost|local|internal|lan|home|intranet)$/.test(h)) throw Error("Private and local network hosts are not allowed.");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) {
    const o=h.split(".").map(Number),[a,b]=o;
    if(o.some(x=>x<0||x>255)) throw Error("Invalid IP address.");
    if(a===0||a===10||a===127||a>=224||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===100&&b>=64&&b<=127)||(a===198&&(b===18||b===19))||(a===192&&b===0)||(a===198&&b===51&&o[2]===100)||(a===203&&b===0&&o[2]===113)) throw Error("Private, reserved, and loopback IP addresses are not allowed.");
  }
  if(h.includes(":")&&(h==="::"||h==="::1"||/^f[cd]/i.test(h)||/^fe[89ab]/i.test(h)||/^::ffff:(127\.|10\.|192\.168\.|169\.254\.)/i.test(h))) throw Error("Private, reserved, and loopback IP addresses are not allowed.");
  if(u.port&&!["80","443","8080","8443"].includes(u.port)) throw Error("This destination port is not allowed.");
}
function isoPath(id,path,search="") { return ISOLATION+encodeURIComponent(id)+"/"+String(path||"").replace(/^\/+/,"")+search; }
function isoUrl(value,base,id) {
  const raw=String(value||"").trim();
  if(!raw||raw.startsWith("#")||/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(raw)||raw.startsWith(ISOLATION)) return value;
  try {
    const u=new URL(raw,base);
    if(u.origin===ASSET_ORIGIN) return isoPath(id,"__opendaw_assets/"+u.pathname.slice(1),u.search)+u.hash;
    if(u.origin!==base.origin||!u.pathname.startsWith(base.pathname)) return value;
    return isoPath(id,u.pathname.slice(base.pathname.length),u.search)+u.hash;
  } catch { return value; }
}
function rewriteHtml(s,base,id) {
  const root=ISOLATION+encodeURIComponent(id)+"/";
  s=s.replace(/\b(src|href|action|poster|data|formaction|cite|manifest|xlink:href|background)\s*=\s*(["'])(.*?)\2/gi,(m,n,q,v)=>n+"="+q+isoUrl(v,base,id)+q);
  s=s.replace(/\bsrcset\s*=\s*(["'])(.*?)\1/gi,(m,q,v)=>/^\s*data:/i.test(v)?m:"srcset="+q+v.split(",").map(c=>{const p=c.trim().split(/\s+/,2);p[0]=isoUrl(p[0],base,id);return p.join(" ");}).join(", ")+q);
  const tag='<base href="'+root+'">';
  if(/<base\b[^>]*>/i.test(s)) s=s.replace(/<base\b[^>]*>/i,t=>/\bhref\s*=/i.test(t)?t.replace(/\bhref\s*=\s*(["']).*?\1/i,'href="'+root+'"'):t.replace(/>$/,' href="'+root+'">'));
  else if(/<head\b[^>]*>/i.test(s)) s=s.replace(/<head\b[^>]*>/i,t=>t+tag); else s=tag+s;
  return s.replace(/(["'])((https?:\/\/[^"'\s<>]+)|\/(?!\/)[^"'\s<>]+)\1/g,(m,q,v)=>q+isoUrl(v,base,id)+q);
}
function rewriteCss(s,base,id) {
  const rw=v=>String(v||"").trim().startsWith("/")||/^https?:\/\//i.test(String(v||"").trim())?isoUrl(v,base,id):v;
  return s.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi,(m,q,v)=>"url("+q+rw(v)+q+")").replace(/@import\s+(["'])(.*?)\1/gi,(m,q,v)=>"@import "+q+rw(v)+q);
}
function rewriteScript(s,base,id) { return s.replace(/(["'])((https?:\/\/[^"'\s<>]+)|\/(?!\/)[^"'\s<>]+)\1/g,(m,q,v)=>q+isoUrl(v,base,id)+q); }
function headersFor(req,isolation=false) {
  const h=new Headers();
  for(const [k,v] of Object.entries(req.headers)) if(v!=null) h.set(k,Array.isArray(v)?v.join(", "):v);
  const blocked=["host","origin","referer","sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-user","cf-connecting-ip","cf-ray","cf-visitor","cf-ipcountry","cf-worker","x-forwarded-for","x-forwarded-proto","x-real-ip"];
  if(isolation) blocked.push("cookie","cookie2","authorization","proxy-authorization","content-length");
  blocked.forEach(k=>h.delete(k));
  if(!isolation) {
    const ua=h.get("x-wk-emulated-user-agent"); h.delete("x-wk-emulated-user-agent");
    if(ua&&ua.length<=512&&/\b(Android|iPhone|iPad|iPod|Mobile)\b/i.test(ua)) {
      h.set("user-agent",ua); for(const k of [...h.keys()]) if(k.toLowerCase().startsWith("sec-ch-ua")) h.delete(k);
      if(ua.includes("Android")&&ua.includes("Chrome/")) {
        const v=ua.includes("Android 14")?"14.0.0":ua.includes("Android 10")?"10.0.0":"14.0.0";
        h.set("sec-ch-ua",'"Chromium";v="120", "Google Chrome";v="120", "Not_A Brand";v="99"');
        h.set("sec-ch-ua-mobile","?1"); h.set("sec-ch-ua-platform",'"Android"'); h.set("sec-ch-ua-platform-version",'"'+v+'"');
        if(ua.includes("Pixel 7")) h.set("sec-ch-ua-model",'"Pixel 7"');
      }
    }
    if(!h.has("user-agent")) h.set("user-agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36");
  }
  return h;
}
function getTarget(req) {
  const q=new URL(req.url,"http://proxy.local").searchParams;
  let value=q.get("url"), b64=q.get("base64_url");
  if(!value&&b64) { try { value=Buffer.from(b64.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(b64.length/4)*4,"="),"base64").toString("utf8"); } catch { throw Object.assign(Error("Invalid base64 encoding"),{status:400}); } }
  if(!value) throw Object.assign(Error("Missing url or base64_url parameter"),{status:400});
  let u; try { u=new URL(value); } catch { throw Object.assign(Error("Invalid target URL"),{status:400}); }
  if(!["http:","https:"].includes(u.protocol)) throw Object.assign(Error("Invalid target protocol"),{status:400});
  return u;
}
async function streamResponse(res,r,stripCors=false) {
  res.status(r.status);
  for(const [k,v] of r.headers) { const l=k.toLowerCase(); if(["content-length","transfer-encoding","connection"].includes(l)||(stripCors&&l.startsWith("access-control-"))) continue; res.setHeader(k,v); }
  corsOut(res);
  if(!r.body) return res.end();
  const reader=r.body.getReader();
  try { while(true) { const {done,value}=await reader.read(); if(done) break; if(!res.write(Buffer.from(value))) await new Promise(ok=>res.once("drain",ok)); } } finally { res.end(); }
}
async function isolation(req,res,u) {
  if(req.method==="OPTIONS") { corsOut(res); return res.status(204).end(); }
  if(u.pathname==="/isolate") {
    if(req.method!=="GET") return text(res,405,"Method not allowed.");
    const raw=u.searchParams.get("url"),id=u.searchParams.get("id");
    if(!raw) return json(res,400,{error:"Missing url parameter."});
    if(!validateId(id)) return json(res,400,{error:"Missing or invalid isolation id."});
    let base; try { base=new URL(raw); validateTarget(base,u.origin); base.hash=""; if(!base.pathname.endsWith("/")) base.pathname+="/"; }
    catch(e) { return json(res,400,{error:e.message||"Invalid isolation URL."}); }
    sessions.set(id,{baseUrl:base.href,origin:base.origin,basePath:base.pathname,expires:Date.now()+TTL*1000});
    return json(res,201,{ok:true,id,url:u.origin+ISOLATION+encodeURIComponent(id)+"/",expiresIn:TTL});
  }
  if(!["GET","HEAD","POST","PUT","PATCH","DELETE"].includes(req.method)) return text(res,405,"Method not allowed.");
  const route=u.pathname.slice(ISOLATION.length),slash=route.indexOf("/"),id=slash<0?route:route.slice(0,slash),path=slash<0?"":route.slice(slash+1);
  if(!validateId(id)) return text(res,400,"Invalid isolation id.");
  const session=sessions.get(id);
  if(!session||session.expires<=Date.now()) { sessions.delete(id); return text(res,404,"This isolation session does not exist or has expired. Reopen the isolated document."); }
  const asset=path.startsWith("__opendaw_assets/"); let base,target;
  try {
    base=new URL(session.baseUrl);
    if(asset) { if(!["GET","HEAD"].includes(req.method)) throw Error("Only GET and HEAD are allowed for openDAW assets."); target=new URL(path.slice(17),ASSET_ORIGIN+"/"); if(target.origin!==ASSET_ORIGIN) throw Error("Invalid openDAW asset path."); }
    else { target=path?new URL(path,base):base; if(target.origin!==session.origin||!target.pathname.startsWith(session.basePath)) throw Error("The requested path is outside this isolation session's base directory."); }
    if(u.search) target.search=u.search; validateTarget(target,u.origin);
  } catch(e) { return text(res,403,e.message||"Invalid isolated asset path."); }
  const h=headersFor(req,true),init={method:req.method,headers:h,redirect:"manual"};
  if(!["GET","HEAD"].includes(req.method)&&req.body?.length) init.body=req.body;
  let upstream; try { upstream=await fetch(target,init); } catch(e) { return text(res,502,"Isolated proxy fetch failed: "+e.message); }
  if(!asset&&upstream.status===404&&req.method==="GET"&&path&&!path.split("/").pop().includes(".")) {
    try { target=new URL(base.href); upstream=await fetch(target,{...init,body:undefined}); } catch(e) { return text(res,502,"Could not load the openDAW app shell: "+e.message); }
  }
  const out=new Headers(upstream.headers);
  ["set-cookie","set-cookie2","content-length","content-encoding","content-md5","cross-origin-embedder-policy","cross-origin-opener-policy","cross-origin-embedder-policy-report-only","cross-origin-opener-policy-report-only"].forEach(k=>out.delete(k));
  const loc=upstream.headers.get("location");
  if(loc&&upstream.status>=300&&upstream.status<400) {
    try {
      const redir=new URL(loc,target);
      if(asset&&redir.origin===ASSET_ORIGIN) out.set("location",isoPath(id,"__opendaw_assets/"+redir.pathname.slice(1),redir.search)+redir.hash);
      else if(redir.origin===base.origin&&redir.pathname.startsWith(session.basePath)) out.set("location",isoPath(id,redir.pathname.slice(session.basePath.length),redir.search)+redir.hash);
      else { validateTarget(redir,u.origin); out.set("location",redir.href); }
    } catch(e) { return text(res,502,"Blocked upstream redirect: "+e.message); }
    for(const [k,v] of Object.entries(cors)) out.set(k,v);
    res.status(upstream.status); for(const [k,v] of out) if(!["content-length","transfer-encoding"].includes(k.toLowerCase())) res.setHeader(k,v); return res.end();
  }
  const ct=(out.get("content-type")||"").toLowerCase(),html=ct.includes("text/html")||ct.includes("application/xhtml+xml"),css=ct.includes("text/css"),js=ct.includes("javascript")||ct.includes("ecmascript");
  let body=upstream.body;
  if(html||css||js) { let s=await upstream.text(); if(html) { s=rewriteHtml(s,base,id); out.set("Document-Isolation-Policy","isolate-and-credentialless"); } else if(css) s=rewriteCss(s,base,id); else s=rewriteScript(s,base,id); body=s; out.delete("etag"); out.delete("last-modified"); }
  for(const [k,v] of Object.entries(cors)) out.set(k,v);
  res.status(upstream.status); for(const [k,v] of out) if(!["content-length","transfer-encoding"].includes(k.toLowerCase())) res.setHeader(k,v);
  if(typeof body==="string") return res.end(body); if(!body) return res.end();
  const reader=body.getReader(); try { while(true) { const {done,value}=await reader.read(); if(done) break; if(!res.write(Buffer.from(value))) await new Promise(ok=>res.once("drain",ok)); } } finally { res.end(); }
}
app.use(express.raw({type:()=>true,limit:process.env.BODY_LIMIT||"100mb"}));
app.use(async(req,res)=>{
  const u=new URL(req.originalUrl,req.protocol+"://"+(req.get("host")||"localhost"));
  if(u.pathname==="/isolate"||u.pathname.startsWith(ISOLATION)) { try { return await isolation(req,res,u); } catch(e) { return text(res,500,e.message||"Isolation proxy error"); } }
  if(req.method==="OPTIONS") { corsOut(res); return res.status(204).end(); }
  let target; try { target=getTarget(req); } catch(e) { return text(res,e.status||400,e.message); }
  const h=headersFor(req),init={method:req.method,headers:h,redirect:"follow"};
  if(!["GET","HEAD"].includes(req.method)&&req.body?.length) init.body=req.body;
  let response=null,failed=false,finalTargetUrl=null;
  try { response=await fetch(target,init); if(response?.redirected) finalTargetUrl=response.url||target.href; } catch { failed=true; }
  if(process.env.USE_CORSFIX_FALLBACK!=="false"&&(failed||(response&&RETRY.has(response.status)))) {
    try {
      const fh=new Headers(h); if(process.env.CORSFIX_API_KEY) fh.set("x-corsfix-key",process.env.CORSFIX_API_KEY);
      const fi={method:req.method,headers:fh,redirect:"follow"}; if(!["GET","HEAD"].includes(req.method)&&req.body?.length) fi.body=req.body;
      const fallback=await fetch(CORSFIX+target.toString(),fi);
      if(fallback.ok||failed) { response=fallback; finalTargetUrl=null; }
    } catch(e) { if(!response) return text(res,502,"Proxy Error: "+e.message); }
  }
  if(!response) return text(res,502,"Proxy request failed");
  if(finalTargetUrl) {
    try {
      const finalUrl=new URL(finalTargetUrl);
      if(finalUrl.protocol==="http:"||finalUrl.protocol==="https:") {
        const responseHeaders=new Headers(response.headers);
        responseHeaders.delete("x-wk-final-url");
        responseHeaders.set("X-WK-Final-URL",finalUrl.href);
        response=new Response(response.body,{status:response.status,statusText:response.statusText,headers:responseHeaders});
      }
    } catch {}
  }
  return streamResponse(res,response,true);
});
server.on("upgrade",async(req,socket,head)=>{
  let target, isolated=false;
  try {
    const incoming=new URL(req.url,"http://"+(req.headers.host||"localhost"));
    if(incoming.pathname.startsWith(ISOLATION)) {
      const route=incoming.pathname.slice(ISOLATION.length),slash=route.indexOf("/");
      const id=slash<0?route:route.slice(0,slash),path=slash<0?"":route.slice(slash+1),session=sessions.get(id);
      if(!validateId(id)||!session||session.expires<=Date.now()) throw Error("Isolation session missing or expired.");
      const base=new URL(session.baseUrl),asset=path.startsWith("__opendaw_assets/");
      if(asset) { target=new URL(path.slice(17),ASSET_ORIGIN+"/"); if(target.origin!==ASSET_ORIGIN) throw Error("Invalid isolated asset path."); }
      else { target=path?new URL(path,base):base; if(target.origin!==session.origin||!target.pathname.startsWith(session.basePath)) throw Error("Path is outside this isolation session."); }
      if(incoming.search) target.search=incoming.search;
      validateTarget(target,incoming.origin); isolated=true;
    } else target=getTarget(req);
  } catch(e) { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"+e.message); return; }
  const h=headersFor(req,isolated); for(const k of ["connection","upgrade","sec-websocket-key","sec-websocket-version","sec-websocket-extensions"]) h.delete(k); if(isolated) h.set("origin",target.origin);
  let upstream;
  try { upstream=new WebSocket(target.toString(),{headers:Object.fromEntries(h),followRedirects:true}); await new Promise((ok,no)=>{upstream.once("open",ok);upstream.once("error",no);}); }
  catch(e) { try { upstream?.terminate(); } catch {} socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nWebSocket Proxy Error: "+e.message); return; }
  wss.handleUpgrade(req,socket,head,client=>{
    const bridge=(from,to)=>{ from.on("message",(data,binary)=>{if(to.readyState===WebSocket.OPEN)to.send(data,{binary});}); from.on("close",(code,reason)=>{if(to.readyState===WebSocket.OPEN)to.close(code,reason.toString());}); from.on("error",()=>{try{to.close();}catch{}}); };
    bridge(client,upstream); bridge(upstream,client);
  });
});
server.listen(PORT,"0.0.0.0",()=>console.log("WatermelonKatana proxy listening on "+PORT));
