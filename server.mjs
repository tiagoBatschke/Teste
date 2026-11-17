import http from 'node:http';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const username = (process.env.AUTH_USERNAME || '').trim();
const password = process.env.AUTH_PASSWORD || '';
const sessionSecret = process.env.SESSION_SECRET || '';
const trustProxy = process.env.TRUST_PROXY === 'true';
const useHttpsCookie = process.env.PUBLIC_HTTPS === 'true';
if (!username || password.length < 12 || sessionSecret.length < 32) {
  console.error('Configure AUTH_USERNAME, AUTH_PASSWORD (mínimo 12 caracteres) e SESSION_SECRET (mínimo 32 caracteres).');
  process.exit(1);
}
const salt = createHmac('sha256', sessionSecret).update('password').digest();
const expectedPassHash = scryptSync(password, salt, 64);
const cookieName = 'lote_session';
const DAY_MS = 24 * 60 * 60 * 1000;
const failures = new Map();
const appHtml = await readFile(path.join(root, 'public', 'app.html'), 'utf8');
const loginHtml = await readFile(path.join(root, 'public', 'login.html'), 'utf8');
function hmac(v) { return createHmac('sha256', sessionSecret).update(v).digest('hex'); }
function parseCookies(req) {
  const out = {};
  for (const v of (req.headers.cookie || '').split(';')) {const idx = v.indexOf('='); if(idx > 0) out[v.slice(0,idx).trim()] = v.slice(idx + 1).trim();}
  return out;
}
function ip(req) {
  if (trustProxy) {
    // Use o ultimo endereco de X-Forwarded-For (um salto de proxy de confianca).
    const ff = req.headers['x-forwarded-for'];
    if(typeof ff === 'string' && ff.trim()) return ff.split(',').at(-1).trim();
  }
  return req.socket.remoteAddress || '';
}
// Sessões assinadas independentes. Não bloqueie por IP ou por dispositivo.
function readSession(req) {
  const token = parseCookies(req)[cookieName];
  if (!token || token.length > 1200) return null;
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || parts[0].length > 700 || !/^[a-f0-9]{64}$/i.test(parts[1])) return null;
  const expected = Buffer.from(hmac(parts[0]), 'hex');
  const provided = Buffer.from(parts[1], 'hex');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
  try {
    const session = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const now = Date.now();
    if (session.u !== username || !Number.isSafeInteger(session.iat) || !Number.isSafeInteger(session.exp)) return null;
    if (session.iat > now + 60_000 || session.exp <= now || session.exp <= session.iat || session.exp - session.iat > DAY_MS) return null;
    return {expires:session.exp};
  } catch { return null; }
}
function isValid(req) { return readSession(req) !== null; }
function issueSession() {
  const now = Date.now();
  const payload = Buffer.from(JSON.stringify({u:username,iat:now,exp:now+DAY_MS,nonce:randomBytes(16).toString('hex')})).toString('base64url');
  return {token: `${payload}.${hmac(payload)}`, expires: now+DAY_MS};
}
function headersForHtml() {return {
  'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};}
function send(res,code,body,headers={}) {res.writeHead(code,{...headers,'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'});res.end(body);}
function json(res,code,body) {send(res,code,JSON.stringify(body),{'Content-Type':'application/json; charset=utf-8'});}
function redirect(res,where) {send(res,303,'',{'Location':where});}
function unsetCookie(){return `${cookieName}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0${useHttpsCookie?'; Secure':''}`;}
function setCookie(token) {return `${cookieName}=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400${useHttpsCookie?'; Secure':''}`;}
function rateLimited(address) {
  const k = hmac(address); const now = Date.now(); let o=failures.get(k);
  if(!o || now-o.start>15*60*1000){o={start:now,n:0};failures.set(k,o);}
  return o.n >= 8;
}
function failed(address){const key=hmac(address);let o=failures.get(key); if(!o||Date.now()-o.start>15*60*1000)o={start:Date.now(),n:0};o.n++;failures.set(key,o);}
function allowedOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // ferramentas HTTP sem origin; POST JSON + SameSite mitigam CSRF de navegadores.
  try { const u = new URL(origin);return u.host.toLowerCase() === (req.headers.host||'').toLowerCase();}catch{return false;}
}
function readJSON(req){return new Promise((resolve,reject)=>{
  if(!(req.headers['content-type']||'').toLowerCase().startsWith('application/json')) {reject(new Error('Cabeçalho de conteúdo inválido'));return;}
  let data='';req.on('data',ch=>{data+=ch;if(data.length>4096){reject(new Error('Requisição longa'));req.destroy();}});req.on('end',()=>{try{resolve(JSON.parse(data));}catch{reject(new Error('JSON inválido'));}});req.on('error',reject);
});}
const server=http.createServer(async (req,res)=>{
 try {
  const p=new URL(req.url||'/',`http://${req.headers.host||'localhost'}`).pathname;
  const method = req.method || 'GET';
  if(p==='/health' && method==='GET'){send(res,200,'ok',{'Content-Type':'text/plain'});return;}
  if(p==='/robots.txt' && method==='GET'){send(res,200,'User-agent: *\nDisallow: /\n',{'Content-Type':'text/plain'});return;}
  if(p==='/api/session' && method==='GET') {const session=readSession(req);if(!session){json(res,401,{ok:false,message:'Sessão expirada. Entre novamente.'});return;}json(res,200,{ok:true,username,expiresAt:session.expires});return;}
  if(p==='/api/login' && method==='POST') {
    if(!allowedOrigin(req)){json(res,403,{ok:false,message:'Origem inválida'});return;}
    const address=ip(req);if(rateLimited(address)){json(res,429,{ok:false,message:'Muitas tentativas. Tente novamente mais tarde.'});return;}
    let credentials;try{credentials=await readJSON(req);}catch{json(res,400,{ok:false,message:'Requisição inválida.'});return;}
    const userOK = typeof credentials?.username === 'string' && credentials.username === username;
    const passInput = typeof credentials?.password === 'string' ? credentials.password : '';
    const passHash = scryptSync(passInput.slice(0,1024),salt,64);
    const passOK = timingSafeEqual(passHash,expectedPassHash);
    if(!userOK || !passOK) {failed(address);json(res,401,{ok:false,message:'Usuário ou senha incorretos.'});return;}
    failures.delete(hmac(address));
    const session=issueSession();
    send(res,200,JSON.stringify({ok:true,expiresAt:session.expires}),{'Content-Type':'application/json; charset=utf-8','Set-Cookie':setCookie(session.token)});
    return;
  }
  if(p==='/api/logout' && method==='POST') {
    if(!allowedOrigin(req)){json(res,403,{ok:false});return;}
    send(res,200,JSON.stringify({ok:true}),{'Content-Type':'application/json; charset=utf-8','Set-Cookie':unsetCookie()});return;
  }
  if((p==='/'||p==='/login') && method==='GET') {
    if(isValid(req)){redirect(res,'/app');return;}
    send(res,200,loginHtml,headersForHtml());return;
  }
  if((p==='/app'||p==='/app/') && method==='GET') {
    if(!isValid(req)){redirect(res,'/login');return;}
    send(res,200,appHtml,headersForHtml());return;
  }
  send(res,404,'Página não encontrada',{'Content-Type':'text/plain; charset=utf-8'});
 } catch(e) {console.error('HTTP handler error:', e?.message || String(e));json(res,500,{ok:false,message:'Erro interno'});}
});
server.listen(port, '0.0.0.0',()=>console.log(`LoteContabil login ativo na porta ${port}`));