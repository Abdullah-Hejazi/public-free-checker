import socket
import unittest
from unittest.mock import patch
from scanner import check_pair, normalized, public_addresses, report_html

OLD = 'https://old.example/old'
NEW = 'https://new.example/new'
HTML = b'<html><link rel="canonical" href="https://new.example/new"></html>'

def transport(records):
    return lambda url: records[url]

class ScannerTests(unittest.TestCase):
    def test_good_migration(self):
        r = check_pair(OLD, NEW, transport({OLD:(301,{'location':NEW},b'',False),NEW:(200,{'content-type':'text/html'},HTML,False)}))
        self.assertEqual(r['verdict'], 'pass')

    def test_wrong_target(self):
        r = check_pair(OLD, NEW, transport({OLD:(200,{'content-type':'text/html'},HTML,False)}))
        self.assertIn('wrong_destination', r['findings'])
        self.assertEqual(r['verdict'], 'fail')

    def test_loop(self):
        r = check_pair(OLD, NEW, transport({OLD:(301,{'location':OLD},b'',False)}))
        self.assertEqual(r['verdict'], 'fail')

    def test_noindex(self):
        r = check_pair(OLD, NEW, transport({OLD:(301,{'location':NEW},b'',False),NEW:(200,{'content-type':'text/html','x-robots-tag':'noindex'},HTML,False)}))
        self.assertIn('noindex_observed', r['findings'])

    def test_bot_block_is_unknown(self):
        r = check_pair(OLD, NEW, transport({OLD:(403,{},b'',False)}))
        self.assertEqual(r['verdict'], 'unknown')

    def test_private_dns_rejected(self):
        for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','192.168.0.1']:
            with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]):
                with self.assertRaises(ValueError): public_addresses('example.com',443)

    def test_mixed_public_private_dns_rejected(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443)),(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError): public_addresses('example.com',443)

    def test_url_restrictions(self):
        for url in ['file:///etc/passwd','http://user:pass@example.com','http://example.com:22','http://example.com/\nfoo']:
            with self.assertRaises(ValueError): normalized(url)

    def test_report_escapes_untrusted_text(self):
        doc = report_html({'created_at':'now','input_sha256':'abc','results':[{'old_url':'<script>alert(1)</script>','expected_url':NEW,'verdict':'unknown','findings':[]}]})
        self.assertNotIn('<script>', doc)

    def test_truncated_response_not_pass(self):
        r = check_pair(OLD, NEW, transport({OLD:(301,{'location':NEW},b'',False),NEW:(200,{'content-type':'text/html'},HTML,True)}))
        self.assertEqual(r['verdict'], 'unknown')

if __name__ == '__main__':
    unittest.main()
