"""
Vulnerable Test Server #2 for PurpleForge Demo
Different vulnerabilities from testserver1 (which had XSS, SQLi, Admin panel)

THIS IS INTENTIONALLY VULNERABLE FOR EDUCATIONAL PURPOSES ONLY
Vulnerabilities included:
- Path Traversal
- Open Redirect
- IDOR (Insecure Direct Object Reference)
- Information Disclosure
- Sensitive File Exposure
- Directory Listing
- Debug Mode Exposure
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import os
import json

# Simulated user database for IDOR demo
USERS = {
    "1": {"id": 1, "name": "Alice Admin", "email": "alice@company.com", "role": "admin", "salary": 95000},
    "2": {"id": 2, "name": "Bob User", "email": "bob@company.com", "role": "user", "salary": 55000},
    "3": {"id": 3, "name": "Charlie Manager", "email": "charlie@company.com", "role": "manager", "salary": 75000},
}

class VulnerableHandler(SimpleHTTPRequestHandler):
    server_version = "Apache/2.2.14 (Ubuntu)"  # Outdated version - info disclosure
    sys_version = "PHP/5.3.2"  # Fake but reveals info

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Add verbose headers - Information Disclosure
        self.protocol_version = "HTTP/1.1"

        # Route handling
        if path == "/":
            self.send_homepage()
        elif path == "/file":
            self.handle_file_download(query)  # Path Traversal vuln
        elif path == "/redirect":
            self.handle_redirect(query)  # Open Redirect vuln
        elif path == "/user":
            self.handle_user(query)  # IDOR vuln
        elif path == "/api/users":
            self.handle_api_users()  # Mass data exposure
        elif path == "/debug":
            self.handle_debug()  # Debug info exposure
        elif path == "/robots.txt":
            self.send_robots()
        elif path == "/.env":
            self.send_env_file()  # Sensitive file
        elif path == "/backup/db.sql":
            self.send_backup()  # Sensitive backup
        elif path == "/.git/config":
            self.send_git_config()  # Git exposure
        elif path == "/uploads":
            self.send_directory_listing()  # Directory listing
        elif path.startswith("/.well-known/"):
            # Serve well-known files for PurpleForge verification
            super().do_GET()
        else:
            self.send_error(404, "Not Found")

    def send_homepage(self):
        html = """<!DOCTYPE html>
<html>
<head><title>VulnApp 2.0 - Demo Application</title></head>
<body>
<h1>VulnApp 2.0 - Test Application</h1>
<p>This is a deliberately vulnerable application for PurpleForge testing.</p>
<h2>Available Endpoints:</h2>
<ul>
    <li><a href="/file?name=readme.txt">/file?name=</a> - Download files</li>
    <li><a href="/redirect?url=https://example.com">/redirect?url=</a> - Redirect service</li>
    <li><a href="/user?id=1">/user?id=</a> - User profile</li>
    <li><a href="/api/users">/api/users</a> - API endpoint</li>
    <li><a href="/debug">/debug</a> - Debug information</li>
    <li><a href="/uploads">/uploads</a> - File uploads</li>
</ul>
<p><small>Server: Apache/2.2.14 | PHP/5.3.2</small></p>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/5.3.2")  # Info disclosure
        self.send_header("Server", "Apache/2.2.14 (Ubuntu)")
        self.send_header("X-Debug-Mode", "enabled")  # Debug leak
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_file_download(self, query):
        """PATH TRAVERSAL VULNERABILITY - accepts ../../../etc/passwd style paths"""
        filename = query.get("name", [""])[0]
        if not filename:
            self.send_error(400, "Missing filename parameter")
            return

        # VULNERABLE: No path sanitization
        # In real app this would allow: /file?name=../../../etc/passwd
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        # Simulate the vulnerability response
        if ".." in filename:
            response = f"[PATH TRAVERSAL DETECTED]\nAttempted path: {filename}\nIn a real vulnerable app, this could expose sensitive files."
        else:
            response = f"File contents of: {filename}\n\nThis is sample file content."

        self.wfile.write(response.encode())

    def handle_redirect(self, query):
        """OPEN REDIRECT VULNERABILITY - redirects to any URL"""
        url = query.get("url", [""])[0]
        if not url:
            self.send_error(400, "Missing url parameter")
            return

        # VULNERABLE: No validation of redirect target
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("X-Redirect-Target", url)  # Exposes redirect in header
        self.end_headers()

        html = f"""<html><body>
<p>Redirecting to: <a href="{url}">{url}</a></p>
<p>[OPEN REDIRECT] - No validation of target URL</p>
</body></html>"""
        self.wfile.write(html.encode())

    def handle_user(self, query):
        """IDOR VULNERABILITY - any user ID accessible without auth"""
        user_id = query.get("id", [""])[0]
        if not user_id:
            self.send_error(400, "Missing id parameter")
            return

        user = USERS.get(user_id)
        if user:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # VULNERABLE: Exposes all user data including salary
            response = json.dumps(user, indent=2)
            self.wfile.write(response.encode())
        else:
            self.send_error(404, "User not found")

    def handle_api_users(self):
        """MASS DATA EXPOSURE - returns all users"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Total-Count", str(len(USERS)))
        self.end_headers()
        # VULNERABLE: Exposes all user data
        response = json.dumps(list(USERS.values()), indent=2)
        self.wfile.write(response.encode())

    def handle_debug(self):
        """DEBUG INFO EXPOSURE"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        debug_info = {
            "debug_mode": True,
            "environment": "development",
            "database_host": "localhost:3306",
            "database_name": "vulnapp_db",
            "database_user": "root",
            "secret_key": "super_secret_key_12345",
            "api_keys": {
                "stripe": "sk_test_xxxx",
                "aws": "AKIA..."
            },
            "internal_ips": ["192.168.1.100", "10.0.0.50"],
            "python_version": "3.12",
            "server_path": "/var/www/vulnapp"
        }
        self.wfile.write(json.dumps(debug_info, indent=2).encode())

    def send_robots(self):
        """Robots.txt with sensitive paths"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        content = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /.git/
Disallow: /.env
Disallow: /debug
Disallow: /api/internal/
"""
        self.wfile.write(content.encode())

    def send_env_file(self):
        """SENSITIVE FILE EXPOSURE - .env file"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        content = """# Environment Configuration
DB_HOST=localhost
DB_USER=admin
DB_PASS=password123
SECRET_KEY=my_super_secret_key
API_KEY=sk-1234567890abcdef
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DEBUG=true
"""
        self.wfile.write(content.encode())

    def send_backup(self):
        """SENSITIVE BACKUP EXPOSURE"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        content = """-- Database Backup
-- vulnapp_db dump

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100)
);

INSERT INTO users VALUES (1, 'admin', 'e10adc3949ba59abbe56e057f20f883e', 'admin@company.com');
INSERT INTO users VALUES (2, 'bob', '5f4dcc3b5aa765d61d8327deb882cf99', 'bob@company.com');
"""
        self.wfile.write(content.encode())

    def send_git_config(self):
        """GIT CONFIG EXPOSURE"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        content = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/company/internal-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = Developer
    email = dev@company.com
"""
        self.wfile.write(content.encode())

    def send_directory_listing(self):
        """DIRECTORY LISTING ENABLED"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = """<!DOCTYPE html>
<html><head><title>Index of /uploads</title></head>
<body>
<h1>Index of /uploads</h1>
<pre>
<a href="../">../</a>
<a href="config_backup.zip">config_backup.zip</a>         2024-01-15 10:30   2.5M
<a href="database_dump.sql">database_dump.sql</a>         2024-01-14 09:15   15M
<a href="private_keys.tar">private_keys.tar</a>          2024-01-10 14:22   512K
<a href="user_data_export.csv">user_data_export.csv</a>      2024-01-08 11:00   8.2M
</pre>
<address>Apache/2.2.14 (Ubuntu) Server at localhost Port 3000</address>
</body></html>"""
        self.wfile.write(html.encode())


def run_server(port=3000):
    server = HTTPServer(("127.0.0.1", port), VulnerableHandler)
    print(f"[*] VulnApp 2.0 Test Server running on http://127.0.0.1:{port}")
    print(f"[*] Vulnerabilities: Path Traversal, Open Redirect, IDOR, Info Disclosure")
    print(f"[*] Press Ctrl+C to stop")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
