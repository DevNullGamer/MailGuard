import os,tempfile
os.environ['DATA_DIR']=tempfile.mkdtemp()
from app.db import init_db,db
def test_schema_has_scan_logging_and_versioning():
 init_db()
 with db() as c:
  tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")};assert {'scans','scan_items','messages'}<=tables
  cols={r['name'] for r in c.execute('PRAGMA table_info(messages)')};assert {'signals','classifier_version','scan_id'}<=cols
