import os,time,secrets,hashlib
from cryptography.fernet import Fernet
from pwdlib import PasswordHash
from base64 import urlsafe_b64encode
ph=PasswordHash.recommended(); attempts={}
def hash_password(p):return ph.hash(p)
def verify_password(p,h):
 try:return ph.verify(p,h)
 except:return False
def key():return urlsafe_b64encode(hashlib.sha256(os.environ['APP_SECRET'].encode()).digest())
def encrypt(s):return Fernet(key()).encrypt(s.encode()).decode()
def decrypt(s):return Fernet(key()).decrypt(s.encode()).decode()
def csrf(s):
 if 'csrf' not in s:s['csrf']=secrets.token_urlsafe(32)
 return s['csrf']
def valid_csrf(s,t):return bool(t) and secrets.compare_digest(s.get('csrf',''),t)
def login_allowed(ip):
 now=time.time();attempts[ip]=[t for t in attempts.get(ip,[]) if now-t<300];return len(attempts[ip])<10
def login_failed(ip):attempts.setdefault(ip,[]).append(time.time())
