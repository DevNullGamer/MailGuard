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
