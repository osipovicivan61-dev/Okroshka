import json
import http.client as http_client
import hashlib
import hmac
import os
import random
import re
import secrets
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8765"))
DATA_DIR = os.path.abspath(os.environ.get(
    "OKROSHKAI_DATA_DIR", os.path.dirname(os.path.abspath(__file__))))
os.makedirs(DATA_DIR, exist_ok=True)
SITE = "http://43.173.73.4:3000"
TMP_RPC = "http://papi2.temp-mail.org/rpc/"
TM_API = "https://api.mail.tm"
UGUU = "https://uguu.se/upload"
KEY_RE = re.compile(r"^sk-[A-Za-z0-9_-]{16,}$")
MAX_KEYS = 5000
MAX_EXTERNAL_TOKENS = 200
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = 129 * 1024 * 1024

JOBS = {}
JOBS_LOCK = threading.Lock()
KEYS = set()
KEYS_LOCK = threading.Lock()
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")
EXTERNAL_TOKENS_FILE = os.path.join(DATA_DIR, "external_api_tokens.json")
ADMIN_TOKEN_FILE = os.path.join(DATA_DIR, "admin_token.txt")
EXTERNAL_TOKENS = {}
EXTERNAL_TOKENS_LOCK = threading.Lock()


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_external_tokens():
    try:
        with open(EXTERNAL_TOKENS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            EXTERNAL_TOKENS.update({key: value for key, value in data.items()
                                    if isinstance(value, dict) and isinstance(value.get("hash"), str)})
    except (FileNotFoundError, json.JSONDecodeError):
        pass


def save_external_tokens():
    tmp = EXTERNAL_TOKENS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(EXTERNAL_TOKENS, f, ensure_ascii=False, indent=2)
    os.replace(tmp, EXTERNAL_TOKENS_FILE)


def get_admin_token():
    configured = os.environ.get("OKROSHKAI_ADMIN_TOKEN", "").strip()
    if configured:
        return configured
    try:
        with open(ADMIN_TOKEN_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        token = "admin_" + secrets.token_urlsafe(32)
        try:
            with open(ADMIN_TOKEN_FILE, "x", encoding="utf-8") as f:
                f.write(token + "\n")
            return token
        except FileExistsError:
            with open(ADMIN_TOKEN_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()


def create_external_token(name):
    name = name.strip()
    if not name or len(name) > 64:
        raise ValueError("name must contain 1-64 characters")
    with EXTERNAL_TOKENS_LOCK:
        if len(EXTERNAL_TOKENS) >= MAX_EXTERNAL_TOKENS:
            raise ValueError("token limit reached")
        token = "okai_" + secrets.token_urlsafe(32)
        token_id = secrets.token_hex(6)
        record = {"id": token_id, "name": name, "prefix": token[:13],
                  "hash": token_hash(token), "created_at": int(time.time())}
        EXTERNAL_TOKENS[token_id] = record
        save_external_tokens()
    return token, {key: record[key] for key in ("id", "name", "prefix", "created_at")}


def valid_external_token(token):
    if not token.startswith("okai_") or len(token) > 128:
        return False
    digest = token_hash(token)
    with EXTERNAL_TOKENS_LOCK:
        return any(hmac.compare_digest(digest, record["hash"])
                   for record in EXTERNAL_TOKENS.values())


def validate_generation_params(params):
    if not isinstance(params, dict):
        raise ValueError("JSON object required")
    prompt = params.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 10000:
        raise ValueError("prompt must contain 1-10000 characters")
    model = params.get("model", "fast")
    if model not in ("fast", "sd2"):
        raise ValueError("model must be fast or sd2")
    ratio = params.get("ratio", "16:9")
    if ratio not in ("16:9", "9:16", "1:1"):
        raise ValueError("ratio must be 16:9, 9:16 or 1:1")
    try:
        duration = int(params.get("duration", 4))
    except (TypeError, ValueError):
        raise ValueError("duration must be 4-15 seconds") from None
    if duration < 4 or duration > 15:
        raise ValueError("duration must be 4-15 seconds")
    refs = params.get("refs", [])
    if not isinstance(refs, list) or len(refs) > 14:
        raise ValueError("refs must be a list of at most 14 items")
    for ref in refs:
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str) or not ref["url"].startswith("https://"):
            raise ValueError("each ref needs an https URL")
        if ref.get("type") not in ("image", "video", "audio"):
            raise ValueError("invalid ref type")
        if ref.get("role") not in ("reference_image", "reference_video", "reference_audio"):
            raise ValueError("invalid ref role")
    return {"prompt": prompt.strip(), "model": model, "ratio": ratio,
            "duration": duration, "refs": refs}


def start_job(params, request_key=None):
    jid = rnd(12)
    with JOBS_LOCK:
        JOBS[jid] = {"state": "pending"}
        if request_key:
            JOBS[jid]["request_key_hash"] = token_hash(request_key)
    threading.Thread(target=run_job, args=(jid, params), daemon=True).start()
    return jid


def load_keys():
    try:
        with open(KEYS_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            KEYS.update(x for x in data if isinstance(x, str) and x.startswith("sk-"))
    except Exception:
        pass


def save_keys():
    try:
        with open(KEYS_FILE, "w") as f:
            json.dump(sorted(KEYS), f)
    except Exception:
        pass


def new_key():
    with KEYS_LOCK:
        if len(KEYS) >= MAX_KEYS:
            raise RuntimeError("key limit")
        k = "sk-" + secrets.token_hex(20)
        KEYS.add(k)
        save_keys()
    return k


def valid_key(k):
    if not k or not KEY_RE.match(k):
        return False
    with KEYS_LOCK:
        return k in KEYS


def rnd(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def http(op, url, data=None, headers=None, timeout=90, retries=4):
    hdrs = {"Connection": "close"}
    if headers:
        hdrs.update(headers)
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        op2 = urllib.request.build_opener() if op is None else op
        try:
            with op2.open(req, timeout=timeout) as r:
                try:
                    body = r.read()
                except http_client.IncompleteRead as e:
                    body = e.partial
                return getattr(r, "status", r.getcode()), body
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except http_client.IncompleteRead as e:
            last = e
            if attempt < retries - 1:
                time.sleep(2)
                continue
            raise
        except Exception as e:
            last = e
            if attempt < retries - 1:
                time.sleep(1)
                continue
            raise
    raise last


def upload_to_uguu(source, length, content_type):
    endpoint = urllib.parse.urlsplit(UGUU)
    connection = http_client.HTTPSConnection(endpoint.hostname, timeout=180)
    try:
        connection.putrequest("POST", endpoint.path)
        connection.putheader("Content-Type", content_type)
        connection.putheader("Content-Length", str(length))
        connection.endheaders()
        remaining = length
        while remaining:
            chunk = source.read(min(64 * 1024, remaining))
            if not chunk:
                raise ValueError("Файл получен не полностью.")
            connection.send(chunk)
            remaining -= len(chunk)
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("Хранилище вернуло слишком большой ответ.")
        return response.status, body
    finally:
        connection.close()


class _NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def site_opener():
    cj = CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op._cj = cj
    return op


def no_redir_opener(op):
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(op._cj), _NoRedir)


def rpc(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    st, body = http(None, TMP_RPC, data=payload, headers={"Content-Type": "application/json"})
    return json.loads(body)


def mailbox_tmp():
    ots = rpc("user.create_ots", {})
    res = rpc("user.get_sid", {"ots": (ots.get("result") or {}).get("ots")})
    sid = (res.get("result") or {}).get("sid")
    if not sid:
        raise RuntimeError("no sid")
    doms = rpc("getdomains", {"sid": sid})
    r = doms.get("result")
    lst = r.get("domains") if isinstance(r, dict) else r
    domain = lst[0] if isinstance(lst, list) and lst else "temp-mail.org"
    addr = rnd(10) + "@" + domain
    rpc("mailbox.new", {"sid": sid, "email": addr})
    return addr


def mailbox_tm():
    st, body = http(None, TM_API + "/domains")
    domain = json.loads(body)["hydra:member"][0]["domain"]
    addr = rnd(10) + "@" + domain
    pw = rnd(12) + "A1"
    http(None, TM_API + "/accounts",
         data=json.dumps({"address": addr, "password": pw}).encode(),
         headers={"Content-Type": "application/json"})
    return addr


def open_session(addr, password):
    op = site_opener()
    name = "u" + rnd(6)
    st, _ = http(op, SITE + "/api/auth/register",
                 data=json.dumps({"name": name, "email": addr, "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    if st != 201:
        raise RuntimeError("register " + str(st))
    st, body = http(op, SITE + "/api/auth/csrf")
    token = json.loads(body).get("csrfToken")
    if not token:
        raise RuntimeError("csrf")
    form = urllib.parse.urlencode(
        {"csrfToken": token, "email": addr, "password": password, "json": "true"}).encode()
    st, _ = http(no_redir_opener(op), SITE + "/api/auth/callback/credentials", data=form,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    if st >= 400:
        raise RuntimeError("login " + str(st))
    st, body = http(op, SITE + "/api/user")
    user = json.loads(body).get("user")
    if not user:
        raise RuntimeError("session")
    return op


def run_job(job_id, params):
    job = JOBS[job_id]
    step = "start"
    try:
        with JOBS_LOCK:
            job["state"] = "running"
        step = "mailbox"
        try:
            addr = mailbox_tmp()
        except Exception:
            addr = mailbox_tm()
        step = "session"
        op = open_session(addr, "Qq" + rnd(10) + "1!")
        model = params.get("model")
        if model not in ("fast", "sd2"):
            model = "fast" if params.get("fast", True) else "sd2"
        is_fast = model == "fast"
        refs = params.get("refs") or []
        has_refs = len(refs) > 0
        if has_refs:
            generation_mode = "multimodal"
            is_fast = False
        else:
            generation_mode = "text_to_video"
        dur = max(4, min(15, int(params.get("duration", 4))))
        if is_fast and dur > 12:
            dur = 12
        step = "create"
        body = {
            "model": "seedance2",
            "prompt": params.get("prompt", ""),
            "params": {
                "duration": dur,
                "aspectRatio": params.get("ratio", "16:9"),
                "resolution": "720p",
                "generateAudio": True,
            },
            "isFast": is_fast,
            "generationMode": generation_mode,
        }
        if has_refs:
            body["referenceUrls"] = refs
        st, resp = http(op, SITE + "/api/generations",
                        data=json.dumps(body).encode(),
                        headers={"Content-Type": "application/json"})
        if st not in (200, 201, 202):
            detail = ""
            try:
                payload = json.loads(resp)
                detail = payload.get("error") or payload.get("message") or ""
                if isinstance(detail, dict):
                    detail = detail.get("message") or str(detail)
            except (ValueError, AttributeError):
                pass
            raise RuntimeError("gen " + str(st) + (": " + str(detail)[:160] if detail else ""))
        gen = json.loads(resp).get("generation") or {}
        gid = gen.get("id")
        if not gid:
            raise RuntimeError("gen id")
        deadline = time.time() + 20 * 60
        step = "poll"
        while time.time() < deadline:
            time.sleep(4)
            try:
                st, resp = http(op, SITE + "/api/generations/%s/status" % gid)
                s = (json.loads(resp).get("status") or "").lower()
            except Exception:
                time.sleep(4)
                continue
            if s == "completed":
                step = "result"
                st, resp = http(op, SITE + "/api/generations/%s" % gid)
                url = (json.loads(resp).get("generation") or {}).get("resultUrl")
                if not url:
                    raise RuntimeError("no url")
                with JOBS_LOCK:
                    job["url"] = url
                    job["state"] = "done"
                return
            if s == "failed":
                err = ""
                try:
                    st2, resp2 = http(op, SITE + "/api/generations/%s" % gid)
                    err = (json.loads(resp2).get("generation") or {}).get("errorMessage") or ""
                except Exception:
                    pass
                if not err:
                    try:
                        err = (json.loads(resp).get("errorMessage") or "")
                    except Exception:
                        pass
                raise RuntimeError("failed" + ((": " + err[:200]) if err else ""))
        raise RuntimeError("timeout")
    except Exception as e:
        with JOBS_LOCK:
            job["state"] = "error"
            job["message"] = step + ": " + str(e)[:280]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, obj=None, raw=None, ctype="application/json"):
        if raw is None:
            raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _admin_authorized(self):
        supplied = self.headers.get("X-Admin-Token", "")
        expected = get_admin_token()
        return bool(supplied and hmac.compare_digest(supplied, expected))

    def _external_token(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        return value.strip() if scheme.lower() == "bearer" else ""

    def _json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("invalid Content-Length") from None
        if length < 1 or length > MAX_BODY_BYTES:
            raise ValueError("JSON body is missing or too large")
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("bad JSON") from None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sd2fast.html"), "rb") as f:
                self._send(200, raw=f.read(), ctype="text/html; charset=utf-8")
            return
        if parsed.path == "/api/status":
            qs = urllib.parse.parse_qs(parsed.query)
            jid = (qs.get("id") or [""])[0]
            job = JOBS.get(jid)
            if not job or "request_key_hash" in job:
                self._send(404, {"error": "unknown"})
                return
            with JOBS_LOCK:
                self._send(200, {"state": job["state"], "url": job.get("url"),
                                 "message": job.get("message")})
            return
        if parsed.path == "/api/admin/tokens":
            if not self._admin_authorized():
                self._send(401, {"error": "invalid admin token"})
                return
            with EXTERNAL_TOKENS_LOCK:
                tokens = [{key: record[key] for key in ("id", "name", "prefix", "created_at")}
                          for record in EXTERNAL_TOKENS.values()]
            self._send(200, {"tokens": sorted(tokens, key=lambda item: item["created_at"], reverse=True)})
            return
        if parsed.path.startswith("/api/v1/generations/"):
            jid = parsed.path.rsplit("/", 1)[-1]
            job = JOBS.get(jid)
            request_key = self.headers.get("X-Request-Key", "")
            if not job or "request_key_hash" not in job or not request_key or not hmac.compare_digest(
                    token_hash(request_key), job["request_key_hash"]):
                self._send(404, {"error": "generation not found"})
                return
            with JOBS_LOCK:
                self._send(200, {"job": jid, "state": job["state"], "url": job.get("url"),
                                 "message": job.get("message")})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/admin/tokens":
            if not self._admin_authorized():
                self._send(401, {"error": "invalid admin token"})
                return
            try:
                data = self._json_body()
                token, record = create_external_token(data.get("name", ""))
            except (ValueError, AttributeError) as e:
                self._send(400, {"error": str(e)})
                return
            self._send(201, {"token": token, "record": record})
            return
        if path == "/api/v1/generations":
            if not valid_external_token(self._external_token()):
                self._send(401, {"error": "invalid API token"})
                return
            try:
                params = validate_generation_params(self._json_body())
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            request_key = "sk-" + secrets.token_hex(20)
            jid = start_job(params, request_key=request_key)
            self._send(202, {"job": jid, "request_key": request_key,
                             "status_url": "/api/v1/generations/" + jid, "state": "pending"})
            return
        if path == "/api/keys":
            try:
                k = new_key()
            except Exception as e:
                self._send(429, {"error": str(e)})
                return
            self._send(200, {"key": k})
            return
        if path == "/api/run":
            try:
                params = self._json_body()
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            if not isinstance(params, dict):
                self._send(400, {"error": "JSON object required"})
                return
            key = (params.get("key") or "").strip() or (self.headers.get("X-Api-Key") or "").strip()
            if not valid_key(key):
                self._send(403, {"error": "invalid key"})
                return
            if not isinstance(params.get("prompt"), str) or not params["prompt"].strip():
                self._send(400, {"error": "empty prompt"})
                return
            if params.get("model") not in ("fast", "sd2"):
                params["model"] = "fast" if params.get("fast", True) else "sd2"
            jid = start_job(params)
            self._send(200, {"job": jid})
            return
        if path == "/proxy/uguu/" or path == "/api/upload":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._send(400, {"error": "Некорректный размер файла."})
                return
            if length <= 0:
                self._send(400, {"error": "Файл не получен."})
                return
            if length > MAX_UPLOAD_BYTES:
                self._send(413, {"error": "Файл больше лимита хранилища (128 МиБ)."})
                return
            ct = self.headers.get("Content-Type") or ""
            if not ct.lower().startswith("multipart/form-data;"):
                self._send(415, {"error": "Ожидается загрузка файла через multipart/form-data."})
                return
            try:
                self.connection.settimeout(180)
                st, resp = upload_to_uguu(self.rfile, length, ct)
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            except Exception as e:
                self._send(502, {"error": "Хранилище недоступно: " + str(e)[:160]})
                return
            try:
                result = json.loads(resp)
            except (ValueError, UnicodeDecodeError):
                self._send(502, {"error": "Хранилище вернуло некорректный ответ."})
                return
            if not isinstance(result, dict):
                self._send(502, {"error": "Хранилище вернуло некорректный ответ."})
                return
            if st != 200 or result.get("success") is False:
                reason = result.get("description") or result.get("error") or "Загрузка отклонена хранилищем."
                self._send(st if 400 <= st <= 599 else 502, {"error": str(reason)[:200]})
                return
            files = result.get("files") or []
            url = files[0].get("url") if files and isinstance(files[0], dict) else None
            if not isinstance(url, str) or not url.startswith("https://"):
                self._send(502, {"error": "Хранилище не вернуло ссылку на файл."})
                return
            self._send(200, {"files": [{"url": url}]})
            return
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/admin/tokens/"):
            self._send(404, {"error": "not found"})
            return
        if not self._admin_authorized():
            self._send(401, {"error": "invalid admin token"})
            return
        token_id = path.rsplit("/", 1)[-1]
        with EXTERNAL_TOKENS_LOCK:
            if token_id not in EXTERNAL_TOKENS:
                self._send(404, {"error": "token not found"})
                return
            del EXTERNAL_TOKENS[token_id]
            save_external_tokens()
        self._send(200, {"revoked": True})


load_keys()
load_external_tokens()

if __name__ == "__main__":
    get_admin_token()
    print("listen on 0.0.0.0:%d" % PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
