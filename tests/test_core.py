import os,tempfile
os.environ['APP_SECRET']='test-secret';os.environ['DATA_DIR']=tempfile.mkdtemp()
from app.classification import HeuristicClassifier
from app.security import encrypt,decrypt,hash_password,verify_password
def test_classifier():
 r=HeuristicClassifier().classify({'authentication_results':'dmarc=fail;dkim=fail;spf=fail','from':'a@x','reply_to':'b@y','urls':['http://1.2.3.4/x'],'threshold':75});assert r.is_spam and r.score>=75
def test_crypto():
 x=encrypt('secret');assert decrypt(x)=='secret';h=hash_password('long password');assert verify_password('long password',h)
