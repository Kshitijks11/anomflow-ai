import json
import os
import urllib.error
import urllib.request
from config import DEFAULT_MODELS, ENV_KEYS, PROVIDER_LABELS

from db.database import BASE
from insights import human_size, human_time, REFERENCE

SETTINGS_PATH = os.path.join(BASE, "settings.json")

SYSTEM = (
    "You explain network-security results to non-technical readers. "
    "You receive measurements for ONE network connection plus the output of a small machine-learning "
    "model (a Random Forest trained only on lab DDoS data from the CIC-IDS2017 dataset, using 5 features). "
    "Write plain English with no markdown, no bullet symbols and no jargon (briefly explain any technical word). "
    "Cover: 1) what this connection most likely is, 2) why the model scored it this way, "
    "3) how worried the reader should be, 4) one or two sensible next checks. "
    "Be honest that the model can be wrong, especially for attack types other than DDoS and for "
    "traffic unlike its training data. Never claim certainty. Keep it under 200 words."
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
        headers={**headers, "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"The AI service returned an error ({e.code}). {detail}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach the AI service. Check your internet. ({e.reason})") from None


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

    data = _post("https://api.openai.com/v1/chat/completions",
                 {"Authorization": f"Bearer {key}"},
                 {"model": model,
                  "messages": [{"role": "system", "content": SYSTEM},
                               {"role": "user", "content": prompt}]})
    return data["choices"][0]["message"]["content"].strip()