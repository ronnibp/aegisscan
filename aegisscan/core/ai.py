"""AI analysis engine — provider-agnostic LLM integration (stdlib only).

Bring-your-own API key. Supported providers (all callable over HTTPS with
urllib, no SDKs):

  openai      OpenAI           api.openai.com        (chat/completions)
  anthropic   Anthropic        api.anthropic.com     (v1/messages)
  google      Google Gemini    generativelanguage…   (generateContent)
  zai         Z.ai / GLM       api.z.ai              (OpenAI-compatible)
  zhipu       Zhipu GLM (CN)   open.bigmodel.cn      (OpenAI-compatible)
  mistral     Mistral AI       api.mistral.ai        (OpenAI-compatible)
  groq        Groq             api.groq.com          (OpenAI-compatible)
  deepseek    DeepSeek         api.deepseek.com      (OpenAI-compatible)
  xai         xAI (Grok)       api.x.ai              (OpenAI-compatible)
  cohere      Cohere           api.cohere.com        (v2/chat)
  openrouter  OpenRouter       openrouter.ai         (OpenAI-compatible)
  custom      any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio, …)

Configuration lives in ``<data-dir>/config.json`` (never committed) and falls
back to well-known environment variables per provider
(OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY/GOOGLE_API_KEY, ZAI_API_KEY,
ZHIPU_API_KEY, MISTRAL_API_KEY, GROQ_API_KEY, DEEPSEEK_API_KEY, XAI_API_KEY,
COHERE_API_KEY, OPENROUTER_API_KEY) or the generic AEGISSCAN_AI_KEY.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .. import __version__

DATA_DIR_NAME = "aegisscan-data"
CONFIG_FILE = "config.json"

# provider -> {label, base_url, default_model, api:"openai"|"anthropic"|"gemini"|"cohere",
#              env:[env var names tried in order], key_url}
PROVIDERS = {
    "openai": {
        "label": "OpenAI", "api": "openai",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "env": ["OPENAI_API_KEY"],
        "key_url": "https://platform.openai.com/api-keys",
    },
    "anthropic": {
        "label": "Anthropic (Claude)", "api": "anthropic",
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-sonnet-4-5",
        "env": ["ANTHROPIC_API_KEY"],
        "key_url": "https://console.anthropic.com/settings/keys",
    },
    "google": {
        "label": "Google Gemini", "api": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.0-flash",
        "env": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "key_url": "https://aistudio.google.com/app/apikey",
    },
    "zai": {
        "label": "Z.ai (GLM)", "api": "openai",
        "base_url": "https://api.z.ai/api/paas/v4",
        "default_model": "glm-4.6",
        "env": ["ZAI_API_KEY", "Z_AI_API_KEY"],
        "key_url": "https://z.ai/manage-apikey/apikey-list",
    },
    "zhipu": {
        "label": "Zhipu AI / GLM (mainland)", "api": "openai",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4.6",
        "env": ["ZHIPU_API_KEY"],
        "key_url": "https://open.bigmodel.cn/usercenter/apikeys",
    },
    "mistral": {
        "label": "Mistral AI", "api": "openai",
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-small-latest",
        "env": ["MISTRAL_API_KEY"],
        "key_url": "https://console.mistral.ai/api-keys",
    },
    "groq": {
        "label": "Groq", "api": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "env": ["GROQ_API_KEY"],
        "key_url": "https://console.groq.com/keys",
    },
    "deepseek": {
        "label": "DeepSeek", "api": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "env": ["DEEPSEEK_API_KEY"],
        "key_url": "https://platform.deepseek.com/api_keys",
    },
    "xai": {
        "label": "xAI (Grok)", "api": "openai",
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-3-mini",
        "env": ["XAI_API_KEY"],
        "key_url": "https://console.x.ai",
    },
    "cohere": {
        "label": "Cohere", "api": "cohere",
        "base_url": "https://api.cohere.com",
        "default_model": "command-r7b-12-2024",
        "env": ["COHERE_API_KEY"],
        "key_url": "https://dashboard.cohere.com/api-keys",
    },
    "openrouter": {
        "label": "OpenRouter (300+ models)", "api": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o-mini",
        "env": ["OPENROUTER_API_KEY"],
        "key_url": "https://openrouter.ai/keys",
    },
    "custom": {
        "label": "Custom OpenAI-compatible endpoint", "api": "openai",
        "base_url": "",                      # user-provided (e.g. http://localhost:11434/v1)
        "default_model": "",
        "env": ["AEGISSCAN_AI_KEY"],
        "key_url": "",
    },
}


class AIError(RuntimeError):
    """Raised with a user-actionable message when an AI call fails."""


# --------------------------------------------------------------------- config
def data_dir() -> str:
    base = os.environ.get("AEGISSCAN_DATA") or os.path.join(os.getcwd(), DATA_DIR_NAME)
    os.makedirs(base, exist_ok=True)
    return base


def config_path() -> str:
    return os.path.join(data_dir(), CONFIG_FILE)


def load_config() -> dict:
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        cfg = {}
    return {k: cfg.get(k, "") for k in ("provider", "api_key", "model", "base_url")}


def save_config(provider: str = "", api_key: str = "", model: str = "",
                base_url: str = "") -> dict:
    if provider and provider not in PROVIDERS:
        raise AIError(f"Unknown provider '{provider}'. Supported: {', '.join(PROVIDERS)}")
    cfg = load_config()
    if provider:
        cfg["provider"] = provider
    if api_key:
        cfg["api_key"] = api_key.strip()
    if model:
        cfg["model"] = model.strip()
    if base_url:
        cfg["base_url"] = base_url.strip().rstrip("/")
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    return cfg


def resolve_ai(cfg: dict | None = None) -> dict:
    """Resolve an effective AI configuration, or raise AIError with guidance."""
    cfg = cfg or load_config()
    provider = (cfg.get("provider") or "").strip().lower()
    if not provider:
        raise AIError(
            "No AI provider configured. Run 'aegisscan ai setup' or set one in the dashboard "
            f"Settings page. Providers: {', '.join(PROVIDERS)}")
    if provider not in PROVIDERS:
        raise AIError(f"Unknown AI provider '{provider}'. Supported: {', '.join(PROVIDERS)}")
    meta = PROVIDERS[provider]

    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        for env_name in meta["env"]:
            v = os.environ.get(env_name, "").strip()
            if v:
                api_key = v
                break
    if not api_key and provider != "custom":
        raise AIError(
            f"No API key for {meta['label']}. Set it with 'aegisscan ai setup --provider {provider} "
            f"--api-key <KEY>' (get one at {meta['key_url']}) or export {meta['env'][0]}.")

    base_url = (cfg.get("base_url") or meta["base_url"]).rstrip("/")
    if not base_url:
        raise AIError("The 'custom' provider requires a base URL, e.g. "
                      "'aegisscan ai setup --provider custom --base-url http://localhost:11434/v1 --model llama3'")

    model = (cfg.get("model") or meta["default_model"]).strip()
    if not model:
        raise AIError(f"No model configured for {meta['label']}. Set one with 'aegisscan ai setup --model <MODEL>'.")

    return {"provider": provider, "label": meta["label"], "api": meta["api"],
            "api_key": api_key, "base_url": base_url, "model": model}


# --------------------------------------------------------------------- client
def _post_json(url: str, headers: dict, body: dict, timeout: int = 90) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"AegisScan/{__version__}", **headers},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:400]
        except Exception:
            pass
        hint = {401: "invalid or expired API key", 403: "key lacks permission / region blocked",
                404: "unknown model or wrong base URL", 429: "rate limit or quota exceeded"}.get(e.code, "")
        raise AIError(f"{meta_url(url)} returned HTTP {e.code}"
                      + (f" ({hint})" if hint else "") + (f": {detail}" if detail else "")) from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise AIError(f"Could not reach {meta_url(url)}: {e}") from e


def meta_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def chat(system: str, user: str, cfg: dict | None = None, timeout: int = 90,
         max_tokens: int = 2048, temperature: float = 0.2) -> str:
    """Send a chat prompt to the configured provider; return the assistant text."""
    eff = resolve_ai(cfg)
    api, key, base, model = eff["api"], eff["api_key"], eff["base_url"], eff["model"]

    if api == "openai":
        data = _post_json(f"{base}/chat/completions",
                          {"Authorization": f"Bearer {key}"},
                          {"model": model,
                           "messages": [{"role": "system", "content": system},
                                        {"role": "user", "content": user}],
                           "max_tokens": max_tokens, "temperature": temperature},
                          timeout)
        try:
            return (data["choices"][0]["message"]["content"] or "").strip()
        except (KeyError, IndexError, TypeError) as e:
            raise AIError(f"Unexpected response shape from {eff['label']}: {json.dumps(data)[:300]}") from e

    if api == "anthropic":
        data = _post_json(f"{base}/v1/messages",
                          {"x-api-key": key, "anthropic-version": "2023-06-01"},
                          {"model": model, "max_tokens": max_tokens, "system": system,
                           "messages": [{"role": "user", "content": user}]},
                          timeout)
        try:
            return "".join(b.get("text", "") for b in data["content"]).strip()
        except (KeyError, TypeError) as e:
            raise AIError(f"Unexpected response shape from Anthropic: {json.dumps(data)[:300]}") from e

    if api == "gemini":
        url = f"{base}/models/{model}:generateContent?key={key}"
        data = _post_json(url, {},
                          {"systemInstruction": {"parts": [{"text": system}]},
                           "contents": [{"role": "user", "parts": [{"text": user}]}],
                           "generationConfig": {"maxOutputTokens": max_tokens,
                                                "temperature": temperature}},
                          timeout)
        try:
            return "".join(p.get("text", "")
                           for c in data["candidates"] for p in c["content"]["parts"]).strip()
        except (KeyError, TypeError, IndexError) as e:
            raise AIError(f"Unexpected response shape from Gemini: {json.dumps(data)[:300]}") from e

    if api == "cohere":
        data = _post_json(f"{base}/v2/chat",
                          {"Authorization": f"Bearer {key}"},
                          {"model": model,
                           "messages": [{"role": "system", "content": system},
                                        {"role": "user", "content": user}],
                           "max_tokens": max_tokens, "temperature": temperature},
                          timeout)
        try:
            return (data["message"]["content"][0]["text"] or "").strip()
        except (KeyError, IndexError, TypeError) as e:
            raise AIError(f"Unexpected response shape from Cohere: {json.dumps(data)[:300]}") from e

    raise AIError(f"Unsupported API kind '{api}'")


# ------------------------------------------------------------------- analysis
def _findings_digest(result_dict: dict, max_findings: int = 80) -> str:
    rows = []
    findings = sorted(result_dict.get("findings", []),
                      key=lambda f: -({"critical": 5, "high": 4, "medium": 3, "low": 2,
                                       "info": 1, "pass": 0}.get(f.get("severity"), 0)))
    for f in findings[:max_findings]:
        rows.append(f"- [{f.get('severity','?').upper()} {f.get('score', 0):.1f}/10] "
                    f"{f.get('title')} @ {f.get('location') or f.get('target')} "
                    f"[{f.get('category')}] MITRE: {','.join(f.get('mitre') or []) or '-'}")
    if len(findings) > max_findings:
        rows.append(f"- … and {len(findings) - max_findings} more lower-severity findings")
    counts = result_dict.get("counts", {})
    targets = ", ".join(t.get("value", "") for t in result_dict.get("targets", []))
    tls = f"TLS grade: {result_dict['tls_grade']}. " if result_dict.get("tls_grade") else ""
    return (f"Scan of: {targets}\nOverall risk score: {result_dict.get('risk_score', 0)}/10. "
            f"{tls}Totals: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
            f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low, {counts.get('info', 0)} info.\n\n"
            f"Findings:\n" + "\n".join(rows))


SYSTEM_PROMPT = (
    "You are a senior application-security engineer writing for the owner of the scanned system. "
    "You receive the findings of an automated AegisScan security scan. Respond in compact Markdown with "
    "exactly these sections:\n"
    "## Executive summary\n(3-5 sentences: what the overall posture is and the biggest risk theme)\n"
    "## Top priorities\n(a numbered list of the 5 findings to fix first, each with why it matters and the concrete fix in one line)\n"
    "## Quick wins\n(bullet list of low-effort/high-impact hardening steps)\n"
    "## Suggested next steps\n(bullet list: deeper testing, process or architectural changes)\n"
    "Be specific and technical. Never invent findings that are not listed. Do not include a preamble."
)


def analyze_result(result_dict: dict, cfg: dict | None = None, timeout: int = 90) -> dict:
    """Generate an AI analysis of a completed scan. Returns {'summary', 'provider', 'model'}."""
    eff = resolve_ai(cfg)
    digest = _findings_digest(result_dict)
    if len(digest) > 60000:
        digest = digest[:60000] + "\n… (truncated)"
    text = chat(SYSTEM_PROMPT, digest, cfg=eff, timeout=timeout)
    return {"summary": text, "provider": eff["provider"], "label": eff["label"], "model": eff["model"]}


def test_connection(cfg: dict | None = None) -> str:
    """Minimal round-trip used by 'aegisscan ai test' and the dashboard."""
    eff = resolve_ai(cfg)
    reply = chat("You are a connectivity test. Reply with exactly: OK",
                 "Reply with exactly: OK", cfg=eff, timeout=30, max_tokens=16)
    return f"Connected to {eff['label']} ({eff['model']}) — response: {reply[:40]}"


def mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 10:
        return key[:2] + "…" + key[-2:]
    return key[:6] + "…" + key[-4:]


def provider_help() -> str:
    lines = []
    for pid, meta in PROVIDERS.items():
        keyinfo = f"key: {meta['key_url']}" if meta["key_url"] else "bring your own endpoint"
        lines.append(f"  {pid:<11} {meta['label']:<28} default model: {meta['default_model'] or '(required)'} — {keyinfo}")
    return "\n".join(lines)
