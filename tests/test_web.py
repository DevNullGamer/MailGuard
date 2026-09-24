import os,tempfile,re
os.environ['DATA_DIR']=tempfile.mkdtemp();os.environ['APP_SECRET']='test-key';os.environ['TRUSTED_HOSTS']='testserver'
from fastapi.testclient import TestClient
from app.main import app
def test_health_and_setup():
 with TestClient(app) as c:
  assert c.get('/health').status_code==200
  html=c.get('/setup').text;t=re.search(r'name="token" value="([^"]+)',html).group(1)
  assert c.post('/setup',data={'username':'admin','password':'a-very-good-test-password','token':t},follow_redirects=False).status_code==303
  assert c.get('/scans').status_code==200

def test_setup_then_logout_login_roundtrip():
 import tempfile,importlib
 # Existing app/database are enough: create a distinct user directly to isolate password verification.
 from app.db import db
 from app.security import hash_password,csrf
 with db() as d:
  d.execute("INSERT OR REPLACE INTO users(username,password_hash) VALUES(?,?)",('roundtrip',hash_password('roundtrip-password-123')))
 with TestClient(app) as c:
  page=c.get('/login').text;t=re.search(r'name="token" value="([^"]+)',page).group(1)
  response=c.post('/login',data={'username':' roundtrip ','password':'roundtrip-password-123','token':t},follow_redirects=False)
  assert response.status_code==303 and response.headers['location']=='/'
