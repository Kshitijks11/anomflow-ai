import json
import os
import urllib.error
import urllib.request

from db.database import BASE
from insights import human_size, human_time, REFERENCE

SETTINGS_PATH = os.path.join(BASE, "settings.json")
DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-4o-mini",
    "google": "gemini-2.5-flash",
    "groq": "llama-3.3-70b-versatile",
}
ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
}
PROVIDER_LABELS = {
    "anthropic": "Anthropic (Claude)",
    "openai": "OpenAI (ChatGPT)",
    "google": "Google (Gemini)",
    "groq": "Groq (free, fast - Llama)",
}

SYSTEM = (
    "You explain network-security results to SOC analysts and security professionals. "
    "You receive measurements for ONE network connection along with the output of a "
    "Random Forest classifier trained on the CIC-IDS2017 dataset. "
    "Write clear, professional, plain English with no markdown formatting and no bullet symbols. "
    "Cover: 1) what this traffic pattern indicates, 2) why the flow features triggered this risk score, "
    "3) the potential threat severity, and 4) recommended response steps. "
    "Be confident, authoritative, and concise. Explain the technical findings directly without "
    "speculating on model limitations or second-guessing the classifier. Keep it under 150 words."
)


class NoKeyError(Exception):
    pass


def load_settings():
    s = {"provider": "anthropic", "api_key": "", "model": DEFAULT_MODELS["anthropic"]}
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            s.update(json.load(f))
    except (OSError, ValueError):
        pass
    return s


def save_settings(s):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def build_prompt(r, importance):
    ref = "\n".join(
        f"- {name}: {v['packets']} packets, {v['bytes']:,} bytes, {v['seconds']} s, "
        f"{v['bytes_per_s']:,} bytes/s, {v['packets_per_s']} packets/s"
        for name, v in REFERENCE.items())
    imp = ", ".join(f"{k} {v:.0%}" for k, v in sorted(importance.items(), key=lambda kv: -kv[1]))
    lines = [
        "One network connection:",
        f"- Likely service: {r['service']}",
        f"- Protocol: {r.get('protocol', '-')}",
        f"- Packets: {int(r['packet_count'])}",
        f"- Data size: {human_size(r['total_bytes'])} ({int(r['total_bytes']):,} bytes)",
        f"- Duration: {human_time(r['duration'])}",
        f"- Data rate: {r['byte_rate']:,.0f} bytes/s",
        f"- Packet rate: {r['packet_rate']:,.1f} packets/s",
        f"Model result: {r['verdict']} (attack probability {r['attack_prob']:.2f}, "
        f"risk level {r['risk_band']}).",
    ]
    if isinstance(r.get("true_label"), str):
        lines.append(f"The dataset's own label for this connection: {r['true_label']}.")
    lines += ["", "Reference values from the training data (medians):", ref, "",
              f"How much the model relies on each measurement: {imp}."]
    return "\n".join(lines)


def _post(url, headers, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={**headers, "content-type": "application/json",
                "user-agent": "ANOMFLOW-AI/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"The AI service returned an error ({e.code}). {detail}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach the AI service. Check your internet. ({e.reason})") from None


def _openai_style(url, key, model, prompt):
    data = _post(url, {"Authorization": f"Bearer {key}"},
                 {"model": model,
                  "messages": [{"role": "system", "content": SYSTEM},
                               {"role": "user", "content": prompt}]})
    return data["choices"][0]["message"]["content"].strip()


def explain_flow(record, importance):
    s = load_settings()
    provider = s["provider"]
    key = s["api_key"].strip() or os.environ.get(ENV_KEYS[provider], "")
    if not key:
        raise NoKeyError("No API key yet. Close this window, click 'AI Settings', and paste your key.")
    model = s["model"].strip() or DEFAULT_MODELS[provider]
    prompt = build_prompt(record, importance)

    if provider == "anthropic":
        data = _post("https://api.anthropic.com/v1/messages",
                     {"x-api-key": key, "anthropic-version": "2023-06-01"},
                     {"model": model, "max_tokens": 600, "system": SYSTEM,
                      "messages": [{"role": "user", "content": prompt}]})
        return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text").strip()

    if provider == "google":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        data = _post(url, {"x-goog-api-key": key},
                     {"systemInstruction": {"parts": [{"text": SYSTEM}]},
                      "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                      "generationConfig": {"maxOutputTokens": 600}})
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts).strip()
        except (KeyError, IndexError):
            reason = data.get("candidates", [{}])[0].get("finishReason", "unknown")
            raise RuntimeError(f"Gemini returned no text (reason: {reason}).") from None

    if provider == "groq":
        return _openai_style("https://api.groq.com/openai/v1/chat/completions", key, model, prompt)

    return _openai_style("https://api.openai.com/v1/chat/completions", key, model, prompt)