import http.server, ssl, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            ln = int(self.headers.get('Content-Length', 0))
            self.rfile.read(ln)
            self.send_response(200); self.end_headers(); self.wfile.write(b'uploaded')
        except Exception:
            try: self.send_response(500); self.end_headers()
            except Exception: pass
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
httpd = S(('0.0.0.0', 8443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('/tmp/srv.pem')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print('upload server on 8443'); httpd.serve_forever()
