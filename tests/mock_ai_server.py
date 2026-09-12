"""Mock OpenAI-compatible chat completions server for testing the AI integration."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        model = body.get("model", "?")
        user_msg = body.get("messages", [{}])[-1].get("content", "")
        reply = (
            "## Executive summary\nThe scanned demo application contains **multiple critical weaknesses** "
            "dominated by code-injection sinks and committed credentials.\n\n"
            "## Top priorities\n"
            "1. Remove `eval()` on request data — direct RCE.\n"
            "2. Rotate the committed database credentials and purge git history.\n"
            "3. Replace string-formatted SQL with parameterized queries.\n\n"
            "## Quick wins\n- Disable Flask debug mode.\n- Pin dependency versions.\n\n"
            "## Suggested next steps\n- Add SAST to CI.\n- Threat-model the upload flow."
        )
        resp = {"id": "mock-1", "object": "chat.completion", "model": model,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": reply}}],
                "usage": {"prompt_tokens": len(user_msg), "completion_tokens": 10}}
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("mock AI on http://127.0.0.1:9777/v1")
    ThreadingHTTPServer(("127.0.0.1", 9777), Handler).serve_forever()
