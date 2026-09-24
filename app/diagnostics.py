import argparse
from .db import init_db,db
from .security import verify_password

def main():
    ap=argparse.ArgumentParser(description='MailGuard safe diagnostics')
    sub=ap.add_subparsers(dest='cmd',required=True)
    sub.add_parser('users')
    c=sub.add_parser('verify-login');c.add_argument('username');c.add_argument('--password',required=True)
    a=ap.parse_args();init_db()
    with db() as conn:
        if a.cmd=='users':
            rows=conn.execute('SELECT username,created_at FROM users ORDER BY id').fetchall()
            print('\n'.join(f"{r['username']}\t{r['created_at']}" for r in rows) or 'NO_USERS')
        elif a.cmd=='verify-login':
            r=conn.execute('SELECT password_hash FROM users WHERE username=?',(a.username.strip(),)).fetchone()
            print('VALID' if r and verify_password(a.password,r['password_hash']) else 'INVALID')
if __name__=='__main__':main()
