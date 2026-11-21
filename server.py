"""Serve the phone-showcase folder on all IPv4 interfaces, port 4190.

Sends the same cross-origin isolation headers as the folder's server.mjs
so the viewer can load. Feedback is stored beside the site, not inside it.

When a Feishu app is configured, every page requires a Feishu login.
Credentials stay beside the site, never inside the web root:

    phone-showcase-feedback/feishu.json
    {"app_id": "cli_xxx", "app_secret": "..."}
"""
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
ASSET_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "素材")
ASSET_MAP = {
    "/models/": os.path.join(ASSET_ROOT, "模型"),
    "/screens/": os.path.join(ASSET_ROOT, "屏保与界面"),
    "/env/": os.path.join(ASSET_ROOT, "环境"),
    "/cards/": os.path.join(ASSET_ROOT, "封面"),
}
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feedback")
INBOX = os.path.join(STORE, "inbox.jsonl")
FEISHU_FILE = os.path.join(STORE, "feishu.json")
PORT = int(os.environ.get("PORT", "4190"))
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
SHARE_HOST = os.environ.get("SHARE_HOST", f"127.0.0.1:{PORT}")
REDIRECT_URI = f"{PUBLIC_URL}/api/feishu/callback" if PUBLIC_URL else f"http://{SHARE_HOST}/api/feishu/callback"
INBOX_LOCK = threading.Lock()
AUTH_LOCK = threading.Lock()
SESSIONS = {}
PENDING = {}
SESSION_TTL = 12 * 60 * 60

TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".wasm": "application/wasm",
    ".data": "application/octet-stream",
    ".usdz": "model/vnd.usdz+zip",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
}

OPEN_PATHS = {"/login", "/api/feishu/start", "/api/feishu/callback", "/api/version"}
VERSION = "iPhoneAir-v5-ipad-ui"


def clip(value, limit, keep_lines=False):
    text = str(value or "")
    if not keep_lines:
        text = text.replace("\r", " ").replace("\n", " ")
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()[:limit]


def feishu_config():
    app_id = os.environ.get("FEISHU_APP_ID", "").strip()
    app_secret = os.environ.get("FEISHU_APP_SECRET", "").strip()
    if app_id and app_secret:
        return app_id, app_secret
    if not os.path.exists(FEISHU_FILE):
        return None
    try:
        with open(FEISHU_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    app_id = str(data.get("app_id") or "").strip()
    app_secret = str(data.get("app_secret") or "").strip()
    if app_id and app_secret:
        return app_id, app_secret
    return None


def read_inbox():
    if not os.path.exists(INBOX):
        return []
    items = []
    with open(INBOX, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    items.reverse()
    return items


def prune_auth(now):
    for key, item in list(SESSIONS.items()):
        if item["exp"] <= now:
            SESSIONS.pop(key, None)
    for key, exp in list(PENDING.items()):
        if exp <= now:
            PENDING.pop(key, None)


def post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url, token):
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def _path(self):
        return urllib.parse.urlsplit(self.path).path

    def _query(self):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def _session(self):
        if not feishu_config():
            return {"name": "", "open": False}
        raw = self.headers.get("Cookie") or ""
        sid = ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "studio_session":
                sid = value
                break
        now = time.time()
        with AUTH_LOCK:
            prune_auth(now)
            item = SESSIONS.get(sid)
            if not item or item["exp"] <= now:
                return None
        return item

    def _require(self):
        if self._path() in OPEN_PATHS or not feishu_config():
            return True
        if self._session():
            return True
        if self._path().startswith("/api/"):
            self._send_json(401, {"error": "login"})
        else:
            self._redirect("/login")
        return False

    def do_GET(self):
        path = self._path()
        if path == "/api/version":
            self._send_json(200, {"version": VERSION})
            return
        if path == "/login":
            if not feishu_config() or self._session():
                self._redirect("/")
                return
            self._login_page("denied" in self._query())
            return
        if path == "/api/feishu/start":
            self._feishu_start()
            return
        if path == "/api/feishu/callback":
            self._feishu_callback()
            return
        if path == "/api/me":
            user = self._session()
            if feishu_config() and not user:
                self._send_json(401, {"error": "login"})
                return
            self._send_json(200, {"name": (user or {}).get("name") or ""})
            return
        if not self._require():
            return
        if path == "/api/feedback":
            with INBOX_LOCK:
                items = read_inbox()
            self._send_json(200, {"items": items})
            return
        if self._serve_asset():
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._require():
            return
        if self._serve_asset(head_only=True):
            return
        super().do_HEAD()

    def _serve_asset(self, head_only=False):
        path = self._path()
        for prefix, target_dir in ASSET_MAP.items():
            if not path.startswith(prefix):
                continue
            file_path = os.path.join(target_dir, path[len(prefix):])
            base_real = os.path.realpath(target_dir)
            real = os.path.realpath(file_path)
            if real != base_real and not real.startswith(base_real + os.sep):
                self.send_error(403, "forbidden")
                return True
            if not os.path.isfile(real):
                self.send_error(404, "not found")
                return True
            try:
                with open(real, "rb") as handle:
                    data = handle.read()
            except OSError:
                self.send_error(404, "not found")
                return True
            self.send_response(200)
            self.send_header("Content-Type", self.guess_type(real))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not head_only:
                self.wfile.write(data)
            return True
        return False

    def do_POST(self):
        if not self._require():
            return
        if self._path() != "/api/feedback":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 12000:
            self._send_json(413, {"error": "too large"})
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "bad json"})
            return
        message = clip(data.get("message"), 1000, True)
        if not message:
            self._send_json(400, {"error": "empty"})
            return
        user = self._session() or {}
        item = {
            "id": str(time.time_ns()),
            "at": time.strftime("%Y-%m-%d %H:%M"),
            "name": clip(data.get("name"), 40) or user.get("name") or "未留名",
            "contact": clip(data.get("contact"), 80),
            "message": message,
        }
        os.makedirs(os.path.dirname(INBOX), exist_ok=True)
        with INBOX_LOCK:
            with open(INBOX, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        self._send_json(200, {"ok": True})

    def _feishu_start(self):
        config = feishu_config()
        if not config:
            self._send_html(503, "飞书登录还没有接上", "<p>分享人还没有完成飞书应用配置。</p>")
            return
        state = secrets.token_urlsafe(24)
        with AUTH_LOCK:
            prune_auth(time.time())
            PENDING[state] = time.time() + 600
        query = urllib.parse.urlencode({
            "client_id": config[0],
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "prompt": "consent",
        })
        self._redirect("https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + query)

    def _feishu_callback(self):
        config = feishu_config()
        query = self._query()
        state = (query.get("state") or [""])[0]
        now = time.time()
        with AUTH_LOCK:
            prune_auth(now)
            exp = PENDING.pop(state, None)
        if not config or not state or not exp or exp <= now or query.get("error"):
            self._redirect("/login?denied=1")
            return
        code = (query.get("code") or [""])[0]
        if not code:
            self._redirect("/login?denied=1")
            return
        try:
            token = post_json("https://accounts.feishu.cn/oauth/v3/token", {
                "grant_type": "authorization_code",
                "client_id": config[0],
                "client_secret": config[1],
                "code": code,
                "redirect_uri": REDIRECT_URI,
            })
            if token.get("code") not in (0, None) or not token.get("access_token"):
                raise RuntimeError(token.get("error") or token.get("msg") or "token")
            profile = get_json(
                "https://open.feishu.cn/open-apis/authen/v1/user_info",
                token["access_token"],
            )
            data = profile.get("data") or {}
            if profile.get("code") not in (0, None) or not data:
                raise RuntimeError(profile.get("msg") or "profile")
        except (OSError, urllib.error.URLError, json.JSONDecodeError, RuntimeError, KeyError) as error:
            print(f"FEISHU LOGIN FAILED {type(error).__name__}", flush=True)
            self._redirect("/login?denied=1")
            return
        sid = secrets.token_urlsafe(32)
        with AUTH_LOCK:
            SESSIONS[sid] = {
                "name": clip(data.get("name") or data.get("en_name") or "飞书用户", 40),
                "open_id": clip(data.get("open_id"), 80),
                "exp": time.time() + SESSION_TTL,
            }
        cookie = f"studio_session={sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age={SESSION_TTL}"
        self._redirect(f"http://{SHARE_HOST}/", cookie)

    def _login_page(self, denied):
        note = "<p class=\"bad\">登录没有完成，请再用飞书试一次。</p>" if denied else ""
        self._send_html(200, "飞书登录", f"""
          <h1>多终端模型平台</h1>
          <p>进入体验前，需要先用飞书登录。</p>
          {note}
          <a class="go" href="/api/feishu/start">使用飞书登录</a>
        """)

    def _send_html(self, code, title, inner):
        page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #111113; color: #f2f2f4;
      font: 15px/1.5 "Segoe UI", sans-serif;
    }}
    main {{
      width: min(420px, calc(100% - 40px));
      padding: 28px 28px 24px; border: 1px solid #2c2c30;
      border-radius: 16px; background: #1c1c1f;
    }}
    h1 {{ margin: 0 0 8px; font-size: 24px; letter-spacing: -0.03em; }}
    p {{ margin: 0 0 18px; color: #8e8e93; }}
    .bad {{ color: #ffb4ab; }}
    .go {{
      display: inline-flex; align-items: center; height: 40px; padding: 0 18px;
      border-radius: 10px; background: #3370ff; color: #fff;
      font-weight: 650; text-decoration: none;
    }}
  </style>
</head>
<body><main>{inner}</main></body>
</html>"""
        body = page.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in TYPES:
            return TYPES[ext]
        return super().guess_type(path)

    def send_head(self):
        if "If-Modified-Since" in self.headers:
            del self.headers["If-Modified-Since"]
        if "If-None-Match" in self.headers:
            del self.headers["If-None-Match"]
        return super().send_head()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()


if __name__ == "__main__":
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    except OSError:
        print(f"端口 {PORT} 已被占用。", flush=True)
        raise SystemExit(1)
    ready = "on" if feishu_config() else "off"
    print(f"SERVING {ROOT} on 0.0.0.0:{PORT} feishu={ready}", flush=True)
    print(f"OPEN http://127.0.0.1:{PORT}/", flush=True)
    server.serve_forever()
