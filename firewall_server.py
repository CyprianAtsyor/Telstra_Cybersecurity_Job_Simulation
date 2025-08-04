# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

host = "localhost"
port = 8000

# Blocking the request and printing a log message
def block_request(self):
    print("Blocking suspicious request from", self.client_address[0])
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request blocked due to suspicious activity"}')

# Allowing the request to response by sending 200 OK
def allow_request(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request allowed"}')

# To Analyze if the request matches the exploit pattern
def is_suspicious(self):
    # We Only interested in the POST requests
    if self.command != "POST":
        return False

    # Parse path, block if it contains .jsp
    parsed_path = urlparse(self.path)
    if ".jsp" not in parsed_path.path:
        return False

    # Checking suspicious headers
    headers = self.headers
    if not (headers.get("c1") == "Runtime" and headers.get("c2") == "<%" and headers.get("suffix") == "%>//"):
        return False

    # Read content length and parse POST data
    content_length = int(headers.get('Content-Length', 0))
    post_data = self.rfile.read(content_length).decode('utf-8')

    # Check payload patterns
    suspicious_patterns = [
        "class.module.classLoader.resources.context.parent.pipeline.first.",
        ".getRuntime().exec(",
        'request.getParameter("cmd")'
    ]

    for pattern in suspicious_patterns:
        if pattern in post_data:
            return True

    return False

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        allow_request(self)

    def do_POST(self):
        if is_suspicious(self):
            block_request(self)
        else:
            allow_request(self)

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s, %s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
