"""Shared helpers: HTTP fetching, file walking, entropy, CLI colours."""

from __future__ import annotations

import gzip
import hashlib
import io
import math
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip",
    ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so",
    ".dylib", ".bin", ".class", ".jar", ".war", ".woff", ".woff2", ".ttf",
    ".eot", ".mp3", ".mp4", ".avi", ".mov", ".sqlite", ".db", ".pyc", ".pyd",
}

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".rb", ".go", ".rs",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".sh", ".bash", ".ps1", ".psm1", ".bat",
    ".cmd", ".sql", ".html", ".htm", ".css", ".scss", ".yml", ".yaml", ".json",
    ".xml", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".md", ".gradle",
    ".properties", ".tf", ".hcl", ".dockerfile", ".plist", ".lock", ".gitignore",
}


def is_text_file(path: str, sample: bytes | None = None) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTS:
        return False
    if sample is None:
        try:
            with open(path, "rb") as fh:
                sample = fh.read(8192)
        except OSError:
            return False
    if b"\x00" in sample:
        return False
    return True


def walk_files(root: str, max_file_size: int = 2 * 1024 * 1024,
               extra_skip: set | None = None, excludes: list | None = None):
    """Yield (path, relpath) for readable text files under root.

    `excludes` is a list of substrings matched against the relative path
    (e.g. ["examples/", "third_party/"]).
    """
    skip = set(SKIP_DIRS) | (extra_skip or set())
    excl = [e.replace("\\", "/").strip("/") for e in (excludes or []) if e.strip()]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".git")]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext in BINARY_EXTS and ext not in (".env",):
                continue
            try:
                if os.path.getsize(path) > max_file_size:
                    continue
            except OSError:
                continue
            if not is_text_file(path):
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")
            if any(x in rel for x in excl):
                continue
            yield path, rel


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def sha1_of(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()


class HttpResponse:
    def __init__(self, status: int, headers: dict, body: bytes, url: str, elapsed: float = 0.0):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body
        self.url = url
        self.elapsed = elapsed

    @property
    def text(self) -> str:
        for enc in ("utf-8", "latin-1"):
            try:
                return self.body.decode(enc)
            except UnicodeDecodeError:
                continue
        return ""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


_NO_VERIFY_CTX = ssl.create_default_context()
_NO_VERIFY_CTX.check_hostname = False
_NO_VERIFY_CTX.verify_mode = ssl.CERT_NONE


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          timeout: int = 15, data: bytes | None = None,
          verify: bool = False, max_redirects: int = 5) -> HttpResponse:
    """Fetch a URL with urllib. verify=False (default) => TLS errors don't block scans."""
    import time
    current, hops = url, 0
    hdrs = {"User-Agent": "AegisScan/1.0 (+security-scanner)", "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    while True:
        req = urllib.request.Request(current, data=data, headers=hdrs, method=method)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=None if verify else _NO_VERIFY_CTX) as resp:
                body = resp.read(10 * 1024 * 1024)
                if resp.headers.get("Content-Encoding") == "gzip":
                    try:
                        body = gzip.decompress(body)
                    except OSError:
                        pass
                elif resp.headers.get("Content-Encoding") == "deflate":
                    try:
                        body = zlib.decompress(body)
                    except zlib.error:
                        pass
                return HttpResponse(resp.status, dict(resp.headers.items()), body,
                                    current, time.time() - t0)
        except urllib.error.HTTPError as e:
            body = e.read(5 * 1024 * 1024) or b""
            return HttpResponse(e.code, dict(e.headers.items()) if e.headers else {}, body,
                                current, time.time() - t0)
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLError) and verify:
                raise
            # retry once without verification if verification failed
            if verify:
                return fetch(url, method, headers, timeout, data, verify=False, max_redirects=hops)
            raise ConnectionError(f"{url}: {e}") from e


def normalize_url(u: str) -> str:
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u


def domain_of(url: str) -> str:
    return urllib.parse.urlparse(normalize_url(url)).netloc.split("@")[-1].split(":")[0]


class Ansi:
    enabled = sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"

    @classmethod
    def _c(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text

    @classmethod
    def bold(cls, t): return cls._c("1", t)
    @classmethod
    def dim(cls, t): return cls._c("2", t)
    @classmethod
    def red(cls, t): return cls._c("91", t)
    @classmethod
    def green(cls, t): return cls._c("92", t)
    @classmethod
    def yellow(cls, t): return cls._c("93", t)
    @classmethod
    def blue(cls, t): return cls._c("94", t)
    @classmethod
    def magenta(cls, t): return cls._c("95", t)
    @classmethod
    def cyan(cls, t): return cls._c("96", t)
    @classmethod
    def gray(cls, t): return cls._c("90", t)

    @classmethod
    def severity(cls, sev: str, text: str | None = None) -> str:
        text = text or sev.upper()
        return {
            "critical": cls.red(cls.bold(text)),
            "high": cls.red(text),
            "medium": cls.yellow(text),
            "low": cls.blue(text),
            "info": cls.gray(text),
            "pass": cls.green(text),
        }.get(sev.lower(), text)
