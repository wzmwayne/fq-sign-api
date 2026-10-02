#!/usr/bin/env python3
"""签名 sidecar: HTTP /sign → 调用 Java/unidbg 工具出 8 个签名头（供 Go 后端旁路调用）。
用法: python3 sidecar.py [port]    依赖: 仅标准库 + 已构建的 fq_download.jar
"""
import json, re, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

JAR = "/tmp/fqdl2/build/libs/fq_download.jar"

def sign(url: str) -> dict:
    p = subprocess.run(["java", "-jar", JAR, "sign", url], capture_output=True, timeout=180)
    t = p.stdout.decode("utf-8", "ignore")
    m = re.search(r"__SIG_BEGIN__(.*?)__SIG_END__", t, re.S)
    if not m:
        raise RuntimeError("签名失败: " + t[-200:])
    lines = m.group(1).replace("\r\n", "\n").split("\n")
    out = {}
    for i in range(0, len(lines) - 1, 2):
        if lines[i].startswith("X-"):
            out[lines[i]] = lines[i + 1]
    return out

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        try:
            res = sign(body["url"])
            data = json.dumps({"headers": res}).encode()
            self.send_response(200)
        except Exception as e:
            data = json.dumps({"error": str(e)}).encode()
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    print(f"sidecar 监听 :{port} (jar={JAR})")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
