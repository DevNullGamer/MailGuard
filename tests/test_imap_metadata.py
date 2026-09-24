from app.imap_client import metadata

def test_html_link_metadata_no_unbound_urlparse():
 raw=b'''From: Spam <spam@example.test>\r\nTo: x@example.test\r\nSubject: Urgent offer\r\nMessage-ID: <1@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><a href="https://evil.test/a">https://good.test/account</a></html>'''
 m=metadata(raw)
 assert 'https://evil.test/a' in m['urls']
 assert m['display_link_mismatch'] is True
