import json,threading,logging
from .db import db,get_config,audit
from .imap_client import ImapClient
from .classification import HybridClassifier,VERSION
log=logging.getLogger('mailguard.scan');lock=threading.Lock()
def configured(c):return all(c.get(k) for k in ('imap_host','imap_user','imap_password','source_folder','review_folder','trash_folder'))
def allowed(c,sender):
 s=(sender or '').lower();d=s.rsplit('@',1)[-1] if '@' in s else ''
 return c.execute("SELECT 1 FROM allowlist WHERE (kind='email' AND value=?) OR (kind='domain' AND value=?)",(s,d)).fetchone() is not None
def _existing(c,folder,uv,uid):return c.execute('SELECT * FROM messages WHERE mailbox=? AND uidvalidity=? AND uid=?',(folder,uv,uid)).fetchone()
def scan(reclassify=False):
 if not lock.acquire(False):return {'ok':False,'error':'mailbox operation already running'}
 scan_id=None
 try:
  with db() as c:
   cfg=get_config(c)
   if not configured(cfg):return {'ok':False,'error':'setup incomplete'}
   threshold=int(cfg.get('spam_threshold',45));cur=c.execute('INSERT INTO scans(mode,classifier_version,threshold) VALUES(?,?,?)',('reclassify' if reclassify else 'normal',VERSION,threshold));scan_id=cur.lastrowid;audit(c,'scan_started',f'scan={scan_id} mode={"reclassify" if reclassify else "normal"} classifier={VERSION}')
  log.info('scan_started scan=%s reclassify=%s classifier=%s',scan_id,reclassify,VERSION)
  processed=spam=ham=allow=errors=0;scores=[]
  try:
   with ImapClient(cfg) as im:
    uv=im.select(cfg['source_folder']);uids=im.uids()[-int(cfg.get('scan_max',5000)):]
    with db() as c:c.execute('UPDATE scans SET candidates=? WHERE id=?',(len(uids),scan_id))
    for uid in uids:
     try:
      with db() as c:old=_existing(c,cfg['source_folder'],uv,uid)
      if old and not reclassify and old['classifier_version']==VERSION:continue
      # Reclassification is restricted to messages still present in source mailbox.
      m=im.fetch(uid);processed+=1;m['threshold']=threshold
      with db() as c:is_allowed=allowed(c,m['sender'])
      if is_allowed:score=0;reasons=['Allowlisted sender/domain'];signals=[{'name':'ALLOWLIST','score':-100,'reason':'Allowlisted sender/domain'}];result='allowlisted';allow+=1
      else:
       cr=HybridClassifier().classify(m);score=cr.score;reasons=cr.reasons;signals=cr.signals;result='spam' if cr.is_spam else 'ham';spam+=int(cr.is_spam);ham+=int(not cr.is_spam)
      scores.append(score)
      # Insert the audit row before remote move so every attempted decision is inspectable.
      with db() as c:
       c.execute('INSERT INTO scan_items(scan_id,uid,sender,subject,score,result,signals) VALUES(?,?,?,?,?,?,?)',(scan_id,uid,m['sender'],m['subject'],score,result,json.dumps(signals)))
      if result=='spam':im.move(uid,cfg['review_folder'])
      with db() as c:
       vals=(m['message_id'],m['sender'],m['sender_name'],m['to'],m['subject'],m['date'],score,json.dumps(reasons),json.dumps(signals),m['preview'],m['authentication_results'],json.dumps(m['urls']),json.dumps(m['attachments']),'quarantined' if result=='spam' else 'not_spam',VERSION,scan_id,cfg['source_folder'],uv,uid)
       c.execute('''INSERT INTO messages(message_id,sender,sender_name,recipient,subject,msg_date,score,reasons,signals,preview,auth_results,urls,attachments,status,classifier_version,scan_id,mailbox,uidvalidity,uid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mailbox,uidvalidity,uid) DO UPDATE SET message_id=excluded.message_id,sender=excluded.sender,sender_name=excluded.sender_name,recipient=excluded.recipient,subject=excluded.subject,msg_date=excluded.msg_date,score=excluded.score,reasons=excluded.reasons,signals=excluded.signals,preview=excluded.preview,auth_results=excluded.auth_results,urls=excluded.urls,attachments=excluded.attachments,status=excluded.status,classifier_version=excluded.classifier_version,scan_id=excluded.scan_id,scanned_at=CURRENT_TIMESTAMP''',vals)
       audit(c,'classified',f'scan={scan_id} result={result} score={score} signals={",".join(x["name"] for x in signals)}',uid)
      log.info('classified scan=%s uid=%s result=%s score=%s sender=%r subject=%r signals=%s',scan_id,uid,result,score,m['sender'],m['subject'][:120],','.join(x['name'] for x in signals))
     except Exception as e:
      errors+=1;log.warning('scan_item_error scan=%s uid=%s type=%s',scan_id,uid,type(e).__name__)
      with db() as c:c.execute('INSERT INTO scan_items(scan_id,uid,result,error,signals) VALUES(?,?,?,?,?)',(scan_id,uid,'error',type(e).__name__,'[]'));audit(c,'scan_item_error',f'scan={scan_id} error={type(e).__name__}',uid,level='WARN')
  except Exception as e:
   errors+=1;log.exception('scan_error scan=%s type=%s',scan_id,type(e).__name__)
  with db() as c:
   c.execute('UPDATE scans SET completed_at=CURRENT_TIMESTAMP,status=?,processed=?,spam=?,ham=?,allowlisted=?,errors=?,min_score=?,max_score=?,score_sum=? WHERE id=?',('completed' if errors==0 else 'partial',processed,spam,ham,allow,errors,min(scores) if scores else None,max(scores) if scores else None,sum(scores),scan_id));audit(c,'scan_completed',f'scan={scan_id} processed={processed} spam={spam} ham={ham} allowlisted={allow} errors={errors}')
  return {'ok':not errors,'scan_id':scan_id,'processed':processed,'spam':spam,'ham':ham,'errors':errors}
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
     if not r:raise RuntimeError('message no longer quarantined')
     # UID after MOVE is provider-dependent. Locate by Message-ID in review folder when source UID is no longer usable.
     st,data=im.c.uid('search',None,'HEADER','Message-ID',r['message_id']) if r['message_id'] else ('NO',[])
     q_uid=int(data[0].split()[-1]) if st=='OK' and data and data[0].split() else r['uid']
     dest=cfg['source_folder'] if action=='keep' else cfg['trash_folder'];im.move(q_uid,dest)
     with db() as c:c.execute('UPDATE messages SET status=?,reviewed_at=CURRENT_TIMESTAMP,action_result=? WHERE id=?',(action+'ed','ok',mid));audit(c,'message_'+action,f'moved to {dest}',q_uid,actor)
     out['succeeded']+=1
    except Exception:out['failed']+=1
  return out
 finally:lock.release()
