import os,json,logging
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request,Form,HTTPException,BackgroundTasks,Query
from fastapi.responses import RedirectResponse,JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .db import init_db,db,get_config,set_config,audit
from .security import *
from .service import scan,review,configured
from .classification import VERSION
logging.basicConfig(level=os.getenv('LOG_LEVEL','INFO'),format='%(asctime)s %(levelname)s %(name)s %(message)s')
@asynccontextmanager
async def life(app):init_db();yield
app=FastAPI(lifespan=life,docs_url=None,redoc_url=None);templates=Jinja2Templates(directory='app/templates')
app.add_middleware(SessionMiddleware,secret_key=os.environ['APP_SECRET'],https_only=os.getenv('COOKIE_SECURE','false').lower()=='true',same_site='strict',max_age=28800)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=[x.strip() for x in os.getenv('TRUSTED_HOSTS','localhost,127.0.0.1').split(',')]);app.mount('/static',StaticFiles(directory='app/static'),name='static')
@app.middleware('http')
async def hdr(req,call):
 r=await call(req);r.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self';style-src 'self';script-src 'self';img-src 'self' data:;frame-ancestors 'none'"});return r
def user(r):return r.session.get('user')
def auth(r):
 if not user(r):raise HTTPException(401)
def render(r,n,**x):return templates.TemplateResponse(n,{'request':r,'user':user(r),'csrf':csrf(r.session),'version':VERSION,**x})
@app.get('/health')
def health():
 try:
  with db() as c:
   c.execute('SELECT 1');cfg=get_config(c);users=c.execute('SELECT count(*) FROM users').fetchone()[0]
  return {'status':'ok','database':'ok','imap_configured':configured(cfg),'setup_required':users==0,'classifier':VERSION}
 except:return JSONResponse({'status':'degraded'},503)
@app.get('/setup')
def setup_get(r:Request):
 with db() as c:x=c.execute('SELECT 1 FROM users').fetchone()
 return RedirectResponse('/login',303) if x else render(r,'setup.html')
@app.post('/setup')
def setup(r:Request,username:str=Form(...),password:str=Form(...),token:str=Form(...)):
 username=username.strip()
 if not valid_csrf(r.session,token):raise HTTPException(403)
 if len(username)<3 or len(password)<12:return render(r,'setup.html',error='Use a username of 3+ and password of 12+ characters.')
 with db() as c:c.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',(username,hash_password(password)));audit(c,'admin_created',actor=username)
 r.session.clear();r.session['user']=username;return RedirectResponse('/settings',303)
@app.get('/login')
def login_get(r:Request):
 with db() as c: exists=c.execute('SELECT 1 FROM users LIMIT 1').fetchone()
 if not exists:return RedirectResponse('/setup',303)
 return render(r,'login.html')
@app.post('/login')
def login(r:Request,username:str=Form(...),password:str=Form(...),token:str=Form(...)):
 username=username.strip()
 if not valid_csrf(r.session,token):raise HTTPException(403)
 ip=r.client.host if r.client else 'unknown'
 if not login_allowed(ip):raise HTTPException(429)
 with db() as c:x=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
 if not x or not verify_password(password,x['password_hash']):
  login_failed(ip)
  with db() as c:audit(c,'login_failed',f'username={username[:64]}',actor='anonymous',level='WARN')
  return render(r,'login.html',error='Invalid credentials')
 attempts.pop(ip,None)
 with db() as c:audit(c,'login_success','',actor=username)
 r.session.clear();r.session['user']=username;return RedirectResponse('/',303)
@app.get('/')
def home(r:Request):
 auth(r)
 with db() as c:scanrow=c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1').fetchone();counts={k:c.execute('SELECT count(*) FROM messages WHERE status=?',(k,)).fetchone()[0] for k in ('quarantined','keeped','deleteed')};events=c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 10').fetchall()
 return render(r,'dashboard.html',scan=scanrow,counts=counts,events=events)
@app.post('/scan')
def scan_now(r:Request,bg:BackgroundTasks,token:str=Form(...),mode:str=Form('normal')):
 auth(r)
 if not valid_csrf(r.session,token):raise HTTPException(403)
 bg.add_task(scan,mode=='reclassify');return RedirectResponse('/scans',303)
@app.get('/scans')
def scans(r:Request):
 auth(r)
 with db() as c:rows=c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 100').fetchall()
 return render(r,'scans.html',scans=rows)
@app.get('/scans/{sid}')
def scan_detail(r:Request,sid:int,result:str|None=Query(None)):
 auth(r)
 with db() as c:s=c.execute('SELECT * FROM scans WHERE id=?',(sid,)).fetchone();items=c.execute('SELECT * FROM scan_items WHERE scan_id=? '+('AND result=? ' if result else '')+'ORDER BY score DESC,id DESC LIMIT 1000',((sid,result) if result else (sid,))).fetchall()
 if not s:raise HTTPException(404)
 buckets=[0]*10
 for x in items:
  if x['score'] is not None:buckets[min(9,max(0,x['score']//10))]+=1
 parsed=[]
 for x in items:d=dict(x);d['signals']=json.loads(d['signals'] or '[]');parsed.append(d)
 return render(r,'scan_detail.html',scan=s,items=parsed,buckets=buckets,filter=result)
@app.get('/review')
def review_page(r:Request,size:int=25):
 auth(r);size=size if size in (20,25,50,100) else 25
 with db() as c:rows=c.execute("SELECT * FROM messages WHERE status='quarantined' ORDER BY score DESC,id DESC LIMIT ?",(size,)).fetchall()
 items=[]
 for x in rows:d=dict(x);d['reasons']=json.loads(d['reasons']);items.append(d)
 return render(r,'review.html',items=items)
@app.post('/review/action')
def action(r:Request,ids:list[int]=Form(...),action:str=Form(...),confirm:str=Form(''),token:str=Form(...)):
 auth(r)
 if not valid_csrf(r.session,token):raise HTTPException(403)
 if action not in ('keep','delete') or (action=='delete' and confirm!='MOVE_TO_TRASH'):raise HTTPException(400)
 review(list(dict.fromkeys(ids)),action,user(r));return RedirectResponse('/review',303)
@app.get('/settings')
def settings(r:Request):
 auth(r)
 with db() as c:return render(r,'settings.html',cfg=get_config(c),allows=c.execute('SELECT * FROM allowlist ORDER BY kind,value').fetchall())
@app.post('/settings')
def save(r:Request,token:str=Form(...),imap_host:str=Form(...),imap_port:int=Form(993),imap_user:str=Form(...),imap_password:str=Form(''),source_folder:str=Form('INBOX'),review_folder:str=Form('SpamReview'),trash_folder:str=Form('Trash'),scan_max:int=Form(5000),spam_threshold:int=Form(45)):
 auth(r)
 if not valid_csrf(r.session,token):raise HTTPException(403)
 if not(1<=imap_port<=65535 and 1<=scan_max<=20000 and 0<=spam_threshold<=100):raise HTTPException(400)
 vals={k:str(v) for k,v in locals().items() if k in ('imap_host','imap_port','imap_user','source_folder','review_folder','trash_folder','scan_max','spam_threshold')};vals['imap_tls']='true'
 with db() as c:set_config(c,vals);set_config(c,{'imap_password':encrypt(imap_password)}) if imap_password else None;audit(c,'settings_updated',actor=user(r))
 return RedirectResponse('/settings',303)
@app.get('/activity')
def activity(r:Request):
 auth(r)
 with db() as c:rows=c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500').fetchall()
 return render(r,'activity.html',events=rows)
