import os
import json
from flask import Flask, request, Response, jsonify, render_template
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.signature import SignatureVerifier
from dotenv import load_dotenv

from utils import get_channel_name, get_permalink, escape_md

load_dotenv()

app = Flask(__name__)

# --- Health / Home routes for Render / testing ---
@app.route("/")
def home():
    return render_template('index.html')

@app.route("/translate", methods=["POST"])
def translate():
    """
    Test endpoint: accepts JSON like {"text": "hei", "target_lang": "en"}
    and returns translated text using your existing detect_and_translate().
    """
    data = request.get_json()
    text = data.get("text", "")
    
    result = detect_and_translate(text)
    if result:
        src_lang, translated = result
        return {
            "input": text,
            "translated": translated,
            "detected_language": src_lang
        }
    else:
        return {
            "input": text,
            "translated": None,
            "detected_language": None
        }


SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
SOURCE_CHANNEL_ID = os.environ.get("SOURCE_CHANNEL_ID", "")
TARGET_CHANNEL_ID = os.environ.get("TARGET_CHANNEL_ID", "")
DEV_SKIP_VERIFICATION = os.environ.get("DEV_SKIP_VERIFICATION", "false").lower() == "true"

TRANSLATION_BACKEND = os.environ.get("TRANSLATION_BACKEND", "googletrans").lower()

client = WebClient(token=SLACK_BOT_TOKEN)
signature_verifier = SignatureVerifier(signing_secret=SLACK_SIGNING_SECRET) if SLACK_SIGNING_SECRET else None

# --- Translation setup ---
translator = None
if TRANSLATION_BACKEND == "googletrans":
    from googletrans import Translator  # unofficial, free
    translator = Translator()
elif TRANSLATION_BACKEND == "deepl":
    import deepl
    DEEPL_API_KEY = os.environ.get("DEEPL_API_KEY", "")
    translator = deepl.Translator(DEEPL_API_KEY)
else:
    raise RuntimeError("Unsupported TRANSLATION_BACKEND. Use 'googletrans' or 'deepl'.")

# Resolve bot user id (after you install and set token)
BOT_USER_ID = None
try:
    auth = client.auth_test()
    BOT_USER_ID = auth["user_id"]
except Exception:
    # Will resolve after you set a valid token and restart
    BOT_USER_ID = None

# Accepted language tags
NORWEGIAN_TAGS = {"no", "nb", "nn"}
SCANDINAVIAN_TAGS = {"no", "nb", "nn", "da", "sv"}

def detect_and_translate(text: str) -> tuple[str, str] | None:
    """
    Returns (src_lang, translated_text) or None if not Scandinavian/Norwegian or empty.
    """
    if not text or not text.strip():
        return None

    if TRANSLATION_BACKEND == "googletrans":
        res = translator.translate(text, dest="en")
        src = (res.src or "").lower()
        if src not in SCANDINAVIAN_TAGS:
            return None
        return src, res.text

    elif TRANSLATION_BACKEND == "deepl":
        # DeepL auto-detect; returns codes like 'NO', 'NB', 'NN', 'DA', 'SV'
        res = translator.translate_text(text, target_lang="EN")
        src = (res.detected_source_lang or "").lower()
        if src not in SCANDINAVIAN_TAGS:
            return None
        return src, res.text

    return None


def verify_slack_signature(req: request) -> bool:
    if DEV_SKIP_VERIFICATION:
        return True
    if not signature_verifier:
        return False
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    signature = req.headers.get("X-Slack-Signature", "")
    body = req.get_data().decode("utf-8")
    return signature_verifier.is_valid(body=body, timestamp=timestamp, signature=signature)


def _parse_source_channel_ids() -> set[str]:
    """Build a set of allowed source channel IDs from env.
    Supports comma-separated SOURCE_CHANNEL_IDS and single SOURCE_CHANNEL_ID.
    """
    ids_from_plural = os.getenv("SOURCE_CHANNEL_IDS", "")
    raw_list = [c.strip() for c in ids_from_plural.split(",") if c.strip()]
    if not raw_list and SOURCE_CHANNEL_ID:
        raw_list = [SOURCE_CHANNEL_ID.strip()]
    return set(raw_list)


def _log_event(message: str, context: dict | None = None):
    try:
        payload = {"message": message}
        if context:
            payload["context"] = context
        print(json.dumps(payload, ensure_ascii=False), flush=True)
    except Exception:
        # Fallback to plain print if serialization fails
        print(f"LOG {message} | CTX={context}", flush=True)


@app.route("/slack/events", methods=["POST"])
def slack_events():
    # Capture raw info early for robust logging
    raw_body = request.get_data(as_text=True)
    headers = {k: request.headers.get(k) for k in [
        "X-Slack-Request-Timestamp",
        "X-Slack-Signature",
        "Content-Type",
        "User-Agent",
    ]}
    _log_event("received_slack_request", {"headers": headers, "body_len": len(raw_body or "")})

    if not verify_slack_signature(request):
        _log_event("ignored_invalid_signature", {"reason": "signature verification failed"})
        return Response("Invalid signature", status=403)

    data = request.get_json(silent=True) or {}
    _log_event("parsed_request_body", {"has_challenge": "challenge" in data, "keys": list(data.keys())})

    # URL verification challenge
    if "challenge" in data:
        _log_event("url_verification_challenge", {"challenge": True})
        return Response(data["challenge"], mimetype="text/plain")

    event = data.get("event", {})
    if not event:
        _log_event("ignored_no_event", {"reason": "missing event key", "body": data})
        return Response(status=200)

    # Only handle new user messages in the source channels
    subtype = event.get("subtype")
    channel = event.get("channel")
    user = event.get("user")
    text = event.get("text", "")
    ts = event.get("ts", "")

    allowed_channels = _parse_source_channel_ids()
    if not allowed_channels:
        _log_event("ignored_no_source_channels_configured", {"reason": "no SOURCE_CHANNEL_IDS/ID configured"})
        return Response(status=200)

    if channel not in allowed_channels:
        _log_event("ignored_wrong_channel", {"reason": "channel not in allowed set", "channel": channel, "allowed_channels": list(allowed_channels)})
        return Response(status=200)

    if subtype is not None:
        _log_event("ignored_non_message_subtype", {"reason": "event subtype present", "subtype": subtype})
        return Response(status=200)

    if BOT_USER_ID and user == BOT_USER_ID:
        _log_event("ignored_own_bot_message", {"reason": "message from bot user id", "bot_user_id": BOT_USER_ID})
        return Response(status=200)

    if not text or not text.strip():
        _log_event("ignored_empty_text", {"reason": "empty or whitespace text", "event": event})
        return Response(status=200)

    # Translate only if Scandinavian/Norwegian
    try:
        result = detect_and_translate(text)
    except Exception as e:
        _log_event("translation_error", {"error": str(e)})
        return Response(status=200)

    if not result:
        # Attempt to log detected language for clarity
        detection_info = {}
        try:
            if TRANSLATION_BACKEND == "googletrans":
                det = translator.detect(text)
                detection_info = {"lang": getattr(det, "lang", None), "confidence": getattr(det, "confidence", None)}
            elif TRANSLATION_BACKEND == "deepl":
                # DeepL has no simple detect-only; we avoid double-charging. Log generic reason.
                detection_info = {"note": "not Scandinavian per detect_and_translate"}
        except Exception as det_err:
            detection_info = {"detect_error": str(det_err)}
        _log_event("ignored_not_scandinavian", {"text_sample": text[:120], "detection": detection_info})
        return Response(status=200)

    src_lang, translated = result

    # Context (use actual event channel, not a single env channel)
    try:
        source_name = get_channel_name(client, channel)
        permalink = get_permalink(client, channel, ts)
    except Exception as ctx_err:
        _log_event("context_lookup_failed", {"error": str(ctx_err), "channel": channel, "ts": ts})
        source_name = channel or "unknown"
        permalink = ""

    original = escape_md(text)
    translated_md = escape_md(translated)

    blocks = [
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn",
                 "text": f"*From* <{permalink}|#{source_name}> · *Detected:* `{src_lang}`"}
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Original:*\n> {original}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*English:*\n{translated_md}"},
        },
    ]

    if not TARGET_CHANNEL_ID:
        _log_event("skipped_post_missing_target_channel", {"reason": "TARGET_CHANNEL_ID not set", "preview_text": translated[:100]})
        return Response(status=200)

    try:
        client.chat_postMessage(
            channel=TARGET_CHANNEL_ID,
            text=f"Translated from #{source_name}: {translated}",
            blocks=blocks,
        )
        _log_event("posted_translation", {"from_channel": channel, "to_channel": TARGET_CHANNEL_ID, "detected": src_lang})
    except SlackApiError as e:
        _log_event("failed_to_post_translation", {"error": e.response.get('error') if hasattr(e, 'response') else str(e)})

    return Response(status=200)

@app.get("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    # Local dev; Slack will reach this via ngrok later
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))

#test