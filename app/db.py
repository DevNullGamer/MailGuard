import os, sqlite3
from contextlib import contextmanager
DATA_DIR=os.getenv('DATA_DIR','/data'); DB_PATH=os.path.join(DATA_DIR,'mailguard.db')
SCHEMA="""PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,mailbox TEXT NOT NULL,uidvalidity INTEGER NOT NULL,uid INTEGER NOT NULL,message_id TEXT,sender TEXT,sender_name TEXT,recipient TEXT,subject TEXT,msg_date TEXT,score INTEGER NOT NULL,reasons TEXT NOT NULL,preview TEXT,auth_results TEXT,urls TEXT,attachments TEXT,status TEXT NOT NULL,scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT,action_result TEXT,UNIQUE(mailbox,uidvalidity,uid));
CREATE TABLE IF NOT EXISTS allowlist(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,value TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(kind,value));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT DEFAULT CURRENT_TIMESTAMP,event TEXT NOT NULL,detail TEXT,uid INTEGER,actor TEXT);
CREATE TABLE IF NOT EXISTS scan_state(id INTEGER PRIMARY KEY CHECK(id=1),running INTEGER NOT NULL DEFAULT 0,started_at TEXT,completed_at TEXT,scanned INTEGER DEFAULT 0,quarantined INTEGER DEFAULT 0,errors INTEGER DEFAULT 0,result TEXT); INSERT OR IGNORE INTO scan_state(id) VALUES(1);"""
def connect():
 os.makedirs(DATA_DIR,exist_ok=True);c=sqlite3.connect(DB_PATH,timeout=30);c.row_factory=sqlite3.Row;return c
@contextmanager
def db():
 c=connect()
 try: yield c;c.commit()
 except: c.rollback();raise
 finally:c.close()
def init_db():
 with connect() as c:c.executescript(SCHEMA)
def get_config(c):return {r['key']:r['value'] for r in c.execute('SELECT key,value FROM config')}
def set_config(c,v):
 for k,x in v.items():c.execute('INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,str(x)))
def audit(c,e,d='',uid=None,actor='system'):c.execute('INSERT INTO audit(event,detail,uid,actor) VALUES(?,?,?,?)',(e,d,uid,actor))
