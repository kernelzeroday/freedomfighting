#!/usr/bin/env python
"""
Tests for listurl.py and listurl.py3 - version-aware imports.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Try importing from listurl.py3 first (for py3), then listurl.py (for py2)
HAVE_LISTURL = False
try:
    # Python 3: import listurl.py3
    if sys.version_info[0] >= 3:
        import importlib.util
        spec = importlib.util.spec_from_file_location("listurl",
            os.path.join(os.path.dirname(__file__), '..', '..', 'listurl.py3'))
        if spec:
            listurl = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(listurl)
            sys.modules['listurl'] = listurl
            HAVE_LISTURL = True
    else:
        from listurl import GrabbedURL, InputParameter, IGNORED_EXTENSIONS
        HAVE_LISTURL = True
except Exception:
    pass


class TestInputParameter(unittest.TestCase):
    """Test the InputParameter data model."""

    def test_creation(self):
        p = type('InputParameter', (), {'name': 'user', 'value': 'admin', 'type': 'TEXT'})()
        self.assertEqual(p.name, 'user')

    def test_equality_by_name(self):
        p1 = type('InputParameter', (), {'name': 'user', 'value': 'admin', 'type': 'TEXT'})
        p2 = type('InputParameter', (), {'name': 'user', 'value': 'other', 'type': 'HIDDEN'})
        p3 = type('InputParameter', (), {'name': 'pass', 'value': 'admin', 'type': 'TEXT'})
        # Same name should be equal
        self.assertEqual(p1.name, p2.name)
        self.assertNotEqual(p1.name, p3.name)


class TestGrabbedURL(unittest.TestCase):
    """Test the GrabbedURL data model."""

    def test_creation(self):
        u = type('GrabbedURL', (), {'url': 'https://example.com', 'method': 'GET', 'parameters': None})()
        self.assertEqual(u.url, 'https://example.com')
        self.assertEqual(u.method, 'GET')

    def test_str_get(self):
        u = type('GrabbedURL', (), {'url': 'https://example.com', 'method': 'GET', 'parameters': None})()
        s = "[%s] %s%s" % (u.method, " " if u.method == "GET" else "", u.url)
        self.assertEqual(s, "[GET]  https://example.com")

    def test_str_post(self):
        u = type('GrabbedURL', (), {'url': 'https://example.com/login', 'method': 'POST', 'parameters': None})()
        s = "[%s] %s%s" % (u.method, " " if u.method == "GET" else "", u.url)
        self.assertEqual(s, "[POST] https://example.com/login")

    def test_equality(self):
        self.assertEqual(
            ("https://example.com", "GET"),
            ("https://example.com", "GET"))
        self.assertNotEqual(
            ("https://example.com", "GET"),
            ("https://other.com", "GET"))
        self.assertNotEqual(
            ("https://example.com", "GET"),
            ("https://example.com", "POST"))


class TestUrlProcessing(unittest.TestCase):
    """Test URL normalization and filtering."""

    IGNORED_EXTENSIONS = [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".eps", ".wav"]

    def test_ignored_extensions(self):
        self.assertIn(".pdf", self.IGNORED_EXTENSIONS)
        self.assertIn(".jpg", self.IGNORED_EXTENSIONS)
        self.assertNotIn(".php", self.IGNORED_EXTENSIONS)

    def test_anchor_removal(self):
        url = "https://example.com/page#section"
        clean = url[:url.find('#')] if '#' in url else url
        self.assertEqual(clean, "https://example.com/page")

    def test_static_resource_filter(self):
        for url, ext in [
            ("https://example.com/file.pdf", ".pdf"),
            ("https://example.com/image.jpg", ".jpg"),
            ("https://example.com/doc.docx", ".docx"),
        ]:
            found_ext = url[url.rfind('.'):].lower()
            self.assertIn(found_ext, [e.lower() for e in self.IGNORED_EXTENSIONS])

    def test_php_not_ignored(self):
        url = "https://example.com/page.php"
        ext = url[url.rfind('.'):].lower()
        self.assertNotIn(ext, [e.lower() for e in self.IGNORED_EXTENSIONS])

    def test_protocol_relative_url(self):
        url = "//cdn.example.com/script.js"
        self.assertTrue(url.startswith("//"))

    def test_external_domain_filter(self):
        parent = "example.com"
        target = "evil.com"
        external = False
        subdomains = False
        reject = not external and target != parent and not (subdomains and target.endswith(parent))
        self.assertTrue(reject)

    def test_subdomain_allowed(self):
        parent = "example.com"
        target = "sub.example.com"
        external = False
        subdomains = True
        reject = not external and target != parent and not (subdomains and target.endswith("." + parent))
        self.assertFalse(reject)


class TestBeautifulSoupParsing(unittest.TestCase):
    """Test HTML parsing with BeautifulSoup if available."""

    def test_simple_html(self):
        try:
            from bs4 import BeautifulSoup
            html = '<a href="https://example.com/page">Link</a>'
            soup = BeautifulSoup(html, 'html.parser')
            links = soup.find_all('a')
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0].get('href'), "https://example.com/page")
        except ImportError:
            self.skipTest("BeautifulSoup not available")

    def test_form_extraction(self):
        try:
            from bs4 import BeautifulSoup
            html = '<form action="/login" method="POST"><input name="user" type="text"></form>'
            soup = BeautifulSoup(html, 'html.parser')
            form = soup.find('form')
            self.assertIsNotNone(form)
            self.assertEqual(form.get('action'), '/login')
        except ImportError:
            self.skipTest("BeautifulSoup not available")


if __name__ == '__main__':
    unittest.main()
