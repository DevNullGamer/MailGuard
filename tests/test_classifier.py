from app.classification import HybridClassifier,VERSION
C=HybridClassifier()
def test_combines_independent_signals():
 m={'from':'Billing <billing@bad.test>','reply_to':'reply@other.test','authentication_results':'dmarc=fail; spf=fail; dkim=fail','subject':'URGENT action required - claim your prize','preview':'Free prize. Claim now. Pay €100. https://1.2.3.4/a','urls':['https://1.2.3.4/a'],'attachments':[],'threshold':45}
 r=C.classify(m);assert r.is_spam;assert r.score>=45;assert len(r.signals)>=5;assert r.version==VERSION
def test_auth_pass_is_negative_evidence():
 r=C.classify({'from':'a@example.com','authentication_results':'dmarc=pass;spf=pass;dkim=pass','subject':'Hello','preview':'Meeting tomorrow','urls':[],'attachments':[],'threshold':45});assert not r.is_spam;assert r.score==0;assert any(x['score']<0 for x in r.signals)
def test_upstream_spam_header_counts():
 r=C.classify({'from':'x@example.com','upstream_is_spam':True,'upstream_spam_score':8,'authentication_results':'','urls':[],'attachments':[],'threshold':40});assert r.is_spam
