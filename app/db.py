import os,sqlite3
from contextlib import contextmanager
DATA_DIR=os.getenv('DATA_DIR','/data');DB_PATH=os.path.join(DATA_DIR,'mailguard.db')
SCHEMA="""PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,mailbox TEXT NOT NULL,uidvalidity INTEGER NOT NULL,uid INTEGER NOT NULL,message_id TEXT,sender TEXT,sender_name TEXT,recipient TEXT,subject TEXT,msg_date TEXT,score INTEGER NOT NULL DEFAULT 0,reasons TEXT NOT NULL DEFAULT '[]',signals TEXT NOT NULL DEFAULT '[]',preview TEXT,auth_results TEXT,urls TEXT DEFAULT '[]',attachments TEXT DEFAULT '[]',status TEXT NOT NULL DEFAULT 'not_spam',classifier_version TEXT,scan_id INTEGER,scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT,action_result TEXT,UNIQUE(mailbox,uidvalidity,uid));
CREATE TABLE IF NOT EXISTS allowlist(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,value TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(kind,value));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT DEFAULT CURRENT_TIMESTAMP,level TEXT DEFAULT 'INFO',event TEXT NOT NULL,detail TEXT,uid INTEGER,actor TEXT);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,started_at TEXT DEFAULT CURRENT_TIMESTAMP,completed_at TEXT,status TEXT DEFAULT 'running',mode TEXT DEFAULT 'normal',classifier_version TEXT,threshold INTEGER,candidates INTEGER DEFAULT 0,processed INTEGER DEFAULT 0,spam INTEGER DEFAULT 0,ham INTEGER DEFAULT 0,allowlisted INTEGER DEFAULT 0,errors INTEGER DEFAULT 0,min_score INTEGER,max_score INTEGER,score_sum INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scan_items(id INTEGER PRIMARY KEY,scan_id INTEGER NOT NULL,uid INTEGER,sender TEXT,subject TEXT,score INTEGER,result TEXT,signals TEXT,error TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""
def connect():
 os.makedirs(DATA_DIR,exist_ok=True);c=sqlite3.connect(DB_PATH,timeout=30);c.row_factory=sqlite3.Row;return c
@contextmanager
def db():
 c=connect()
 try:yield c;c.commit()
 except:c.rollback();raise
 finally:c.close()
def columns(c,t):return {x['name'] for x in c.execute(f'PRAGMA table_info({t})')}
def migrate(c):
 needed={'signals':"TEXT NOT NULL DEFAULT '[]'",'classifier_version':'TEXT','scan_id':'INTEGER'}
 cols=columns(c,'messages')
 for k,v in needed.items():
  if k not in cols:c.execute(f'ALTER TABLE messages ADD COLUMN {k} {v}')
 # Previous releases used scan_state. Keep it if present but v2 uses scans.
def init_db():
 with connect() as c:c.executescript(SCHEMA);migrate(c)
def get_config(c):return {x['key']:x['value'] for x in c.execute('SELECT key,value FROM config')}
def set_config(c,d):
 for k,v in d.items():c.execute('INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,str(v)))
def audit(c,event,detail='',uid=None,actor='system',level='INFO'):c.execute('INSERT INTO audit(level,event,detail,uid,actor) VALUES(?,?,?,?,?)',(level,event,detail,uid,actor))
