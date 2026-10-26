from http.server import SimpleHTTPRequestHandler, HTTPServer

PORT = 8000

# Each path redirects (HTTP 302) to the next one
ROUTES = {
    "/start": f"http://127.0.0.1:{PORT}/hop2",
    "/hop2": f"http://localhost:{PORT}/hop3",
    "/hop3": f"http://127.0.0.1:{PORT}/hop4",
    "/hop4": f"http://localhost:{PORT}/hop5",
    "/hop5": f"http://127.0.0.1:{PORT}/fake-login.html",
}


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ROUTES:
            self.send_response(302)
            self.send_header("Location", ROUTES[path])
            self.end_headers()
            return

        # Page-level redirect (meta refresh) instead of an HTTP redirect
        if path == "/client":
            body = b'<meta http-equiv="refresh" content="0; url=/fake-login.html">'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        super().do_GET()


print(f"Serving on http://localhost:{PORT}  (Ctrl+C to stop)")
HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()