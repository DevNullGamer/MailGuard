from dataclasses import dataclass,asdict
from email.utils import parseaddr
from urllib.parse import urlparse
import re
VERSION='hybrid-v2.1'
@dataclass
class Signal:
    name:str; score:int; reason:str
@dataclass
class Result:
    is_spam:bool; score:int; reasons:list[str]; signals:list[dict]; version:str=VERSION
class Classifier:
    def classify(self,m): raise NotImplementedError
class HybridClassifier(Classifier):
    SHORTENERS={'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','is.gd','cutt.ly','tiny.cc'}
    URGENCY=re.compile(r'\b(urgent|immediately|act now|action required|account suspended|verify (?:your )?account|payment required|final notice|limited time)\b',re.I)
    PROMO=re.compile(r'\b(free|winner|won|prize|bonus|claim now|guaranteed|earn money|special offer|exclusive offer|discount|unsubscribe)\b',re.I)
    MONEY=re.compile(r'(?:[$€£]\s?\d{2,}|\b\d{2,}%\s*(?:off|discount)|\b(?:bitcoin|crypto|investment|loan|casino|jackpot)\b)',re.I)
    def classify(self,m):
        s=[]
        def add(n,p,r,cond=True):
            if cond:s.append(Signal(n,p,r))
        auth=(m.get('authentication_results') or '').lower()
        add('DMARC_FAIL',22,'DMARC failed','dmarc=fail' in auth);add('SPF_FAIL',12,'SPF failed','spf=fail' in auth);add('DKIM_FAIL',10,'DKIM failed','dkim=fail' in auth);add('SPF_SOFTFAIL',7,'SPF softfail','spf=softfail' in auth)
        add('DMARC_PASS',-5,'DMARC passed','dmarc=pass' in auth);add('DKIM_PASS',-3,'DKIM passed','dkim=pass' in auth);add('SPF_PASS',-2,'SPF passed','spf=pass' in auth)
        sender=parseaddr(m.get('from',''))[1].lower();reply=parseaddr(m.get('reply_to',''))[1].lower();sd=sender.rsplit('@',1)[-1] if '@' in sender else '';rd=reply.rsplit('@',1)[-1] if '@' in reply else ''
        add('REPLYTO_MISMATCH',12,'Sender domain differs from Reply-To',reply and sd and rd and sd!=rd)
        add('MISSING_MESSAGE_ID',5,'Missing Message-ID',not m.get('message_id'));add('MISSING_SENDER',10,'Missing/invalid sender address',not sender)
        urls=m.get('urls',[]);domains={urlparse(u).hostname.lower() for u in urls if urlparse(u).hostname}
        add('MANY_LINKS',6,'Many links in message',len(urls)>=8);add('MANY_DOMAINS',7,'Links span many domains',len(domains)>=4)
        add('IP_URL',14,'Link contains an IP address',any(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',d) for d in domains))
        add('PUNYCODE_URL',10,'Punycode link domain',any('xn--' in d for d in domains));add('SHORTENER',6,'URL-shortening service used',bool(domains & self.SHORTENERS))
        add('LINK_MISMATCH',12,'Displayed URL differs from link destination',m.get('display_link_mismatch',False))
        text=((m.get('subject') or '')+' '+(m.get('preview') or ''))[:12000]
        promo=len(self.PROMO.findall(text));urg=len(self.URGENCY.findall(text));money=len(self.MONEY.findall(text))
        add('PROMO_LANGUAGE',min(14,4+promo*2),'Multiple promotional/spam-like phrases',promo>=2);add('URGENCY_LANGUAGE',min(12,4+urg*3),'Urgent or coercive language',urg>=1);add('MONEY_LANGUAGE',min(10,3+money*2),'Financial/promotion language',money>=1)
        add('HTML_ONLY',5,'HTML-only message',m.get('html_only',False));add('IMAGE_HEAVY',6,'Image-heavy message with little text',m.get('image_count',0)>=2 and len(text)<250)
        add('LINK_HEAVY',8,'Many links relative to text',len(urls)>=4 and len(text)<800)
        dangerous={'.exe','.js','.vbs','.scr','.iso','.img','.html','.htm','.lnk','.zip'};names=[a.get('name','').lower() for a in m.get('attachments',[])]
        add('RISKY_ATTACHMENT',12,'Potentially risky attachment extension',any(any(n.endswith(x) for x in dangerous) for n in names))
        # Naturally occurring provider / upstream anti-spam headers are useful evidence.
        hs=(m.get('spam_headers') or '').lower();xscore=m.get('upstream_spam_score')
        add('UPSTREAM_SPAM',28,'Upstream/provider marked message as spam',m.get('upstream_is_spam',False));add('UPSTREAM_SCORE',min(20,max(0,int(xscore or 0)*2)),'High upstream spam score',xscore is not None and float(xscore)>=5)
        raw=sum(x.score for x in s);score=max(0,min(100,raw));threshold=int(m.get('threshold',45))
        return Result(score>=threshold,score,[x.reason for x in s if x.score>0] or ['No strong spam indicators'],[asdict(x) for x in s])
