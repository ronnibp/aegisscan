"""DEMO: Intentionally vulnerable application for testing AegisScan.

DO NOT deploy this anywhere. It exists so users can verify the scanner works.
"""
import os
import pickle
import random

import django  # noqa
import requests
import yaml
from flask import Flask, request

AWS_ACCESS_KEY_ID = "AKIA1234fakekeyEXAMPLE"      # FAKE value for scanner demo only
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE!Y"  # FAKE
STRIPE_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dcDEMO"   # FAKE test-mode value
GITHUB_TOKEN = "Ghp_FAKE0TOKEN0FOR0SCANNER0DEM0x0"    # FAKE
DATABASE_URL = "postgres://admin:S3cr3tP@ss@db.internal:5432/prod"

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    # sast: SQL built by string formatting
    query = f"SELECT * FROM users WHERE id = {uid}"
    return run_query(query)


@app.route("/calc")
def calc():
    # sast: eval of user input
    return str(eval(request.args.get("expr")))


@app.route("/render")
def render_template_string():
    name = request.args.get("name")
    # sast: reflected XSS via innerHTML (client would consume this)
    payload = {"html": name}
    return str(payload["html"]).replace("NAME", "<script>document.write(location.hash)</script>")


@app.route("/run")
def run_cmd():
    import subprocess
    host = request.args.get("host")
    # sast: shell=True command injection
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "https://example.com")
    # sast: TLS verification disabled + SSRF-ish
    return requests.get(url, verify=False).text


@app.route("/load")
def load_yaml():
    data = request.get_data()
    # sast: unsafe yaml load
    return str(yaml.load(data))


@app.route("/state")
def load_state():
    # sast: pickle on request data
    return str(pickle.loads(request.get_data()))


@app.route("/go")
def go():
    # sast: open redirect via unvalidated parameter
    from flask import redirect
    return redirect(request.args.get("next"))


@app.route("/download")
def download():
    # sast: path traversal via send_file + os.path.join
    from flask import send_file
    p = os.path.join("/srv/files", request.args.get("p", ""))
    return send_file(p)


@app.route("/session")
def session_token():
    # sast: JWT signature verification disabled
    import jwt as pyjwt
    return str(pyjwt.decode(request.args.get("t", ""), "secret", verify=False))


def make_token():
    # sast: insecure randomness
    return "".join(random.choice("abcdef0123456789") for _ in range(32))


def hash_password(pw: str) -> str:
    import hashlib
    # sast: weak hash
    return hashlib.md5(pw.encode()).hexdigest()


def run_query(q):
    raise NotImplementedError


app.run(debug=True, host="0.0.0.0")
