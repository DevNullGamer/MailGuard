import imaplib,ssl,email,re
from email.header import decode_header,make_header
from email.utils import parseaddr
from .security import decrypt
URL=re.compile(r'https?://[^\s<>"\']+',re.I)
def dec(v):
 try:return str(make_header(decode_header(v or '')))
 except:return v or ''
def metadata(raw):
 msg=email.message_from_bytes(raw);preview='';attachments=[]
 for p in msg.walk():
  fn=p.get_filename()
  if fn:attachments.append({'name':dec(fn)[:200],'type':p.get_content_type()[:100]})
  if not preview and p.get_content_type()=='text/plain' and p.get_content_disposition()!='attachment':
   try:preview=p.get_payload(decode=True).decode(p.get_content_charset() or 'utf-8','replace')[:500].replace('\x00','')
   except:pass
 return {'from':dec(msg.get('From')),'sender':parseaddr(dec(msg.get('From')))[1].lower(),'sender_name':parseaddr(dec(msg.get('From')))[0],'to':dec(msg.get('To')),'subject':dec(msg.get('Subject'))[:500],'date':dec(msg.get('Date'))[:100],'message_id':dec(msg.get('Message-ID'))[:500],'reply_to':dec(msg.get('Reply-To')),'authentication_results':dec(msg.get('Authentication-Results'))[:2000],'preview':preview,'urls':URL.findall(preview)[:50],'attachments':attachments,'attachment_count':len(attachments)}
class ImapClient:
 def __init__(self,cfg):self.cfg=cfg
 def __enter__(self):
  h=self.cfg['imap_host'];p=int(self.cfg.get('imap_port',993));self.c=imaplib.IMAP4_SSL(h,p,ssl_context=ssl.create_default_context()) if self.cfg.get('imap_tls','true')=='true' else imaplib.IMAP4(h,p);self.c.login(self.cfg['imap_user'],decrypt(self.cfg['imap_password']));return self
 def __exit__(self,*a):
  try:self.c.logout()
  except:pass
 def test(self):return self.c.noop()[0]=='OK'
 def select(self,f):
  st,_=self.c.select(f)
  if st!='OK':raise RuntimeError('Cannot select mailbox')
  _,d=self.c.response('UIDVALIDITY');return int(d[0]) if d else 0
 def uids(self):
  st,d=self.c.uid('search',None,'ALL')
  if st!='OK':raise RuntimeError('UID search failed')
  return [int(x) for x in d[0].split()]
 def fetch(self,uid):
  st,d=self.c.uid('fetch',str(uid),'(BODY.PEEK[])')
  if st!='OK' or not d or not isinstance(d[0],tuple):raise KeyError(uid)
  return metadata(d[0][1])
 def move(self,uid,dest):
  self.c.create(dest);st,_=self.c.uid('MOVE',str(uid),dest)
  if st=='OK':return
  st,_=self.c.uid('COPY',str(uid),dest)
  if st!='OK':raise RuntimeError('COPY failed')
  st,_=self.c.uid('STORE',str(uid),'+FLAGS.SILENT',r'(\Deleted)')
  if st!='OK':raise RuntimeError(r'STORE \Deleted failed')
