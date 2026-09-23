import os,tempfile
os.environ['APP_SECRET']='test-secret';os.environ['DATA_DIR']=tempfile.mkdtemp();os.environ['TRUSTED_HOSTS']='testserver'
from fastapi.testclient import TestClient
from app.main import app
def test_health():
 with TestClient(app) as c:assert c.get('/health').status_code==200
