import imaplib,ssl,email,re,html
from email.header import decode_header,make_header
from email.utils import parseaddr
from .security import decrypt
URL=re.compile(r'https?://[^\s<>"\']+',re.I);HREF=re.compile(r'href\s*=\s*["\']([^"\']+)',re.I);DISPLAY_URL=re.compile(r'https?://[^\s<>]+',re.I)
def dec(v):
 try:return str(make_header(decode_header(v or '')))
 except:return v or ''
def _text(part,limit=12000):
 try:return part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8','replace')[:limit].replace('\x00','')
 except:return ''
def metadata(raw):
 msg=email.message_from_bytes(raw);plain='';html_body='';attachments=[];images=0
 for p in msg.walk():
  typ=p.get_content_type();fn=p.get_filename()
  if typ.startswith('image/'):images+=1
  if fn:attachments.append({'name':dec(fn)[:200],'type':typ[:100]})
  if not fn and typ=='text/plain' and not plain:plain=_text(p)
  if not fn and typ=='text/html' and not html_body:html_body=_text(p)
 cleaned=re.sub(r'<[^>]{0,1000}>',' ',html_body);cleaned=html.unescape(re.sub(r'\s+',' ',cleaned))[:12000]
 body=plain or cleaned;urls=(URL.findall(plain)+HREF.findall(html_body))[:100]
 shown=DISPLAY_URL.findall(cleaned);dest={re.sub(r'^www\.','',(urlparse(u).hostname or '').lower()) for u in urls if u.lower().startswith(('http://','https://'))}
 from urllib.parse import urlparse
 shown_domains={re.sub(r'^www\.','',(urlparse(u).hostname or '').lower()) for u in shown}
 mismatch=bool(shown_domains and dest and shown_domains-dest)
 auth='; '.join(dec(msg.get_all('Authentication-Results',[])))[:4000];spam='; '.join(dec(x) for h in ('X-Spam-Status','X-Spam-Flag','X-Spam','X-Microsoft-Antispam','X-Forefront-Antispam-Report') for x in msg.get_all(h,[]))[:4000]
 is_spam=bool(re.search(r'(^|[ ;])(yes|true|spam)([ ;]|$)',spam,re.I));up=None
 for h in ('X-Spam-Score','X-Spam-Level'):
  v=dec(msg.get(h));m=re.search(r'-?\d+(?:\.\d+)?',v)
  if m:
   try:up=float(m.group());break
   except:pass
 return {'from':dec(msg.get('From')),'sender':parseaddr(dec(msg.get('From')))[1].lower(),'sender_name':parseaddr(dec(msg.get('From')))[0],'to':dec(msg.get('To')),'subject':dec(msg.get('Subject'))[:500],'date':dec(msg.get('Date'))[:100],'message_id':dec(msg.get('Message-ID'))[:500],'reply_to':dec(msg.get('Reply-To')),'authentication_results':auth,'spam_headers':spam,'upstream_is_spam':is_spam,'upstream_spam_score':up,'preview':body[:1000],'urls':urls,'attachments':attachments,'attachment_count':len(attachments),'html_only':bool(html_body and not plain),'image_count':images,'display_link_mismatch':mismatch}
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
