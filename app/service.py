import json,threading
from .db import db,get_config,audit
from .imap_client import ImapClient
from .classification import HeuristicClassifier
lock=threading.Lock()
def configured(c):return all(c.get(k) for k in ('imap_host','imap_user','imap_password','source_folder','review_folder','trash_folder'))
def allowed(c,s):
 s=(s or '').lower();d=s.rsplit('@',1)[-1] if '@' in s else ''
 return c.execute("SELECT 1 FROM allowlist WHERE (kind='email' AND value=?) OR (kind='domain' AND value=?)",(s,d)).fetchone() is not None
def scan():
 if not lock.acquire(False):return {'ok':False,'error':'busy'}
 try:
  with db() as c:cfg=get_config(c)
  if not configured(cfg):return {'ok':False,'error':'setup incomplete'}
  scanned=q=errs=0
  try:
   with ImapClient(cfg) as im:
    uv=im.select(cfg['source_folder'])
    for uid in im.uids()[-int(cfg.get('scan_max',500)):]:
     with db() as c:
      if c.execute('SELECT 1 FROM messages WHERE mailbox=? AND uidvalidity=? AND uid=?',(cfg['source_folder'],uv,uid)).fetchone():continue
     try:
      m=im.fetch(uid);scanned+=1
      with db() as c:
       if allowed(c,m['sender']):score=0;reasons=['Allowlisted'];spam=False
       else:m['threshold']=cfg.get('spam_threshold',75);r=HeuristicClassifier().classify(m);score=r.score;reasons=r.reasons;spam=r.is_spam
      status='not_spam'
      if spam:im.move(uid,cfg['review_folder']);status='quarantined';q+=1
      with db() as c:c.execute('INSERT INTO messages(mailbox,uidvalidity,uid,message_id,sender,sender_name,recipient,subject,msg_date,score,reasons,preview,auth_results,urls,attachments,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(cfg['source_folder'],uv,uid,m['message_id'],m['sender'],m['sender_name'],m['to'],m['subject'],m['date'],score,json.dumps(reasons),m['preview'],m['authentication_results'],json.dumps(m['urls']),json.dumps(m['attachments']),status))
     except Exception as e:errs+=1
  except Exception:errs+=1
  with db() as c:c.execute('UPDATE scan_state SET running=0,completed_at=CURRENT_TIMESTAMP,scanned=?,quarantined=?,errors=?,result=? WHERE id=1',(scanned,q,errs,'ok' if not errs else 'partial'));audit(c,'scan_completed',f'scanned={scanned} quarantined={q} errors={errs}')
  return {'ok':not errs,'scanned':scanned,'quarantined':q,'errors':errs}
 finally:lock.release()
def review(ids,action,actor):
 if not lock.acquire(False):return {'requested':len(ids),'succeeded':0,'failed':len(ids)}
 try:
  with db() as c:cfg=get_config(c)
  out={'requested':len(ids),'succeeded':0,'failed':0}
  with ImapClient(cfg) as im:
   uv=im.select(cfg['review_folder'])
   for mid in ids:
    try:
     with db() as c:r=c.execute("SELECT * FROM messages WHERE id=? AND status='quarantined'",(mid,)).fetchone()
     if not r or r['uidvalidity']!=uv:raise RuntimeError('state changed')
     dest=cfg['source_folder'] if action=='keep' else cfg['trash_folder'];im.move(r['uid'],dest)
     with db() as c:c.execute('UPDATE messages SET status=?,reviewed_at=CURRENT_TIMESTAMP,action_result=? WHERE id=?',(action+'ed','ok',mid));audit(c,'message_'+action,f'moved to {dest}',r['uid'],actor)
     out['succeeded']+=1
    except:out['failed']+=1
  return out
 finally:lock.release()
