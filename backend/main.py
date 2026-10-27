from __future__ import annotations
import os, re, time, asyncio
from datetime import datetime, timezone
from urllib.parse import quote
from typing import Optional
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, 'backend', '.env'))
BRAVE_KEY = os.getenv('BRAVE_SEARCH_API_KEY', '').strip()
HIBP_KEY = os.getenv('HIBP_API_KEY', '').strip()
app = FastAPI(title='Digital Twin OSINT API', version='2.0.0')
_requests: dict[str, list[float]] = {}
RATE_LIMIT, WINDOW_SECONDS = 8, 60

class ScanRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    context: str = Field(default='', max_length=160)
    email: Optional[str] = Field(default=None, max_length=254)
    authorized: bool
    @field_validator('name', 'context')
    @classmethod
    def strip_text(cls, value: str) -> str: return value.strip()
    @field_validator('email')
    @classmethod
    def validate_email(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip(): return None
        value = value.strip()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value): raise ValueError('Enter a valid email address')
        return value

@app.middleware('http')
async def rate_limit(request: Request, call_next):
    if request.url.path == '/api/scan':
        key = request.client.host if request.client else 'unknown'
        now = time.time(); recent = [t for t in _requests.get(key, []) if now-t < WINDOW_SECONDS]
        if len(recent) >= RATE_LIMIT: return JSONResponse(status_code=429, content={'detail':'Rate limit reached. Wait one minute.'})
        recent.append(now); _requests[key] = recent
    return await call_next(request)

@app.get('/')
async def home(): return FileResponse(os.path.join(BASE_DIR, 'index.html'))

@app.get('/api/health')
async def health(): return {'ok':True,'brave_configured':bool(BRAVE_KEY),'breach_check_configured':bool(HIBP_KEY)}

async def brave_search(query: str, client: httpx.AsyncClient) -> list[dict]:
    if not BRAVE_KEY: return []
    r = await client.get('https://api.search.brave.com/res/v1/web/search', params={'q':query,'count':8,'search_lang':'en','safesearch':'moderate'}, headers={'X-Subscription-Token':BRAVE_KEY,'Accept':'application/json'})
    if r.status_code == 401: raise HTTPException(502, 'Brave Search rejected the API key.')
    if r.status_code == 429: raise HTTPException(503, 'Brave Search rate limit reached.')
    r.raise_for_status(); out=[]
    for x in r.json().get('web',{}).get('results',[]):
        url=x.get('url','')
        if not url.startswith(('https://','http://')): continue
        desc=x.get('description','')
        desc=re.sub(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}','[email redacted]',desc,flags=re.I)
        desc=re.sub(r'(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)','[phone number redacted]',desc)
        out.append({'title':x.get('title','Untitled result'),'url':url,'description':desc[:700],'age':x.get('age') or x.get('page_age') or ''})
    return out

async def github_search(name: str, context: str, client: httpx.AsyncClient) -> list[dict]:
    q=name+(' '+context if context else '')
    r=await client.get('https://api.github.com/search/users',params={'q':q,'per_page':5},headers={'Accept':'application/vnd.github+json','User-Agent':'DigitalTwinOSINT'})
    if r.status_code==403: return []
    r.raise_for_status(); out=[]
    for x in r.json().get('items',[])[:5]:
        d=await client.get(x.get('url',''),headers={'Accept':'application/vnd.github+json','User-Agent':'DigitalTwinOSINT'})
        p=d.json() if d.status_code==200 else {}
        out.append({'login':x.get('login',''),'url':x.get('html_url',''),'name':p.get('name'),'bio':(p.get('bio') or '')[:240],'public_repos':p.get('public_repos',0),'followers':p.get('followers',0)})
    return out

async def hibp_check(email: Optional[str], client: httpx.AsyncClient) -> dict:
    if not email: return {'status':'not_provided','breaches':[]}
    if not HIBP_KEY: return {'status':'not_configured','breaches':[],'message':'HIBP_API_KEY is not configured.'}
    r=await client.get('https://haveibeenpwned.com/api/v3/breachedAccount/'+quote(email,safe=''),params={'truncateResponse':'false','IncludeUnverified':'false'},headers={'hibp-api-key':HIBP_KEY,'user-agent':'DigitalTwinOSINT/1.0','Accept':'application/json'})
    if r.status_code==404: return {'status':'checked','breaches':[]}
    if r.status_code in (401,429) or r.status_code>=500: return {'status':'unavailable','breaches':[],'message':'Breach provider unavailable or rejected the request.'}
    r.raise_for_status(); out=[]
    for b in r.json(): out.append({'name':b.get('Name','Unknown breach'),'description':re.sub(r'<[^>]*>','',b.get('Description') or '')[:650],'date':b.get('BreachDate',''),'data_classes':b.get('DataClasses',[]),'source_url':'https://haveibeenpwned.com/'})
    return {'status':'checked','breaches':out}

@app.post('/api/scan')
async def scan(body: ScanRequest):
    if not body.authorized: raise HTTPException(403,'Confirm this is your own audit or an explicitly authorized audit.')
    name=body.name.strip()
    if len(name)<2: raise HTTPException(422,'Enter at least two characters.')
    context=body.context.strip(); identity='"'+name+'"'+(' "'+context+'"' if context else '')
    queries=[identity,identity+' public profile',identity+' portfolio OR publications OR interview']
    if context: queries=[identity,'"'+name+'" "'+context+'" public profile']
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0,connect=7.0),follow_redirects=True) as client:
            gathered=await asyncio.gather(*(brave_search(q,client) for q in queries),return_exceptions=True) if BRAVE_KEY else []
            web_results=[]; seen=set()
            for result in gathered:
                if isinstance(result,Exception): continue
                for item in result:
                    if item['url'] not in seen: seen.add(item['url']); web_results.append(item)
            web_results=web_results[:20]
            try: profiles=await github_search(name,context,client)
            except Exception: profiles=[]
            breach=await hibp_check(body.email,client)
    except HTTPException: raise
    except httpx.TimeoutException: raise HTTPException(504,'A source timed out. Try again; no results were fabricated.')
    except Exception as exc: raise HTTPException(502,'An upstream source failed. Check server configuration.') from exc
    sources=['Brave Search API' if BRAVE_KEY else 'Brave Search (not configured)','GitHub public API']
    if body.email and HIBP_KEY: sources.append('Have I Been Pwned API')
    return {'status':'complete' if BRAVE_KEY else 'partial','completed_at':datetime.now(timezone.utc).isoformat(),'sources':sources,'web_results':web_results,'github_profiles':profiles,'breach_check':breach,'limitations':['Indexed search is not a complete crawl; results may be stale or incomplete.','Names can match different people. Verify each result manually.','GitHub matches are candidates, not proof of identity.','Breach results contain incident metadata only, never passwords or dump contents.','A missing result does not prove there is no exposure.']}
