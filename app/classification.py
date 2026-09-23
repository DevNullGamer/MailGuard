from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlparse
import re
@dataclass
class Result:is_spam:bool;score:int;reasons:list[str]
class Classifier:
 def classify(self,m):raise NotImplementedError
class HeuristicClassifier(Classifier):
 def classify(self,m):
  score=0;reasons=[];auth=(m.get('authentication_results') or '').lower()
  for k,p,l in [('dmarc=fail',32,'DMARC failed'),('dkim=fail',18,'DKIM failed'),('spf=fail',18,'SPF failed'),('spf=softfail',9,'SPF softfail')]:
   if k in auth:score+=p;reasons.append(l)
  sender=parseaddr(m.get('from',''))[1].lower();reply=parseaddr(m.get('reply_to',''))[1].lower();sd=sender.rsplit('@',1)[-1] if '@' in sender else '';rd=reply.rsplit('@',1)[-1] if '@' in reply else ''
  if reply and sd!=rd:score+=18;reasons.append('Sender domain differs from Reply-To')
  domains={urlparse(u).hostname or '' for u in m.get('urls',[])}
  if len(domains)>=5:score+=12;reasons.append('Many link domains')
  if any(re.search(r'(xn--|\d{1,3}(?:\.\d{1,3}){3})',d) for d in domains):score+=20;reasons.append('Suspicious link domain')
  if m.get('attachment_count',0)>=5:score+=8;reasons.append('Unusually many attachments')
  score=min(score,100);return Result(score>=int(m.get('threshold',75)),score,reasons or ['No high-confidence spam indicators'])
