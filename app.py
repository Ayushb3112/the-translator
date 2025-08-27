import os
import json
from flask import Flask, request, Response, jsonify
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
    return "The Translator API is live! Slack events are being processed."

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

NORWEGIAN_TAGS = {"no", "nb", "nn"}  # Norwegian, Bokmål, Nynorsk

# Expand your accepted tags
NORWEGIAN_TAGS = {"no", "nb", "nn"}
SCANDINAVIAN_TAGS = {"no", "nb", "nn", "da", "sv"}   # include Danish & Swedish

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
        print("DEBUG:", res.text, res.src)
        src = (res.detected_source_lang or "").lower()
        if src not in SCANDINAVIAN_TAGS:
            return None
        return src, str(res)

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

@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_signature(request):
        return Response("Invalid signature", status=403)

    data = request.get_json(silent=True) or {}
    # URL verification challenge
    if "challenge" in data:
        return Response(data["challenge"], mimetype="text/plain")

    event = data.get("event", {})
    if not event:
        return Response(status=200)

    # Only handle new user messages in the source channel
    # Ignore edits, bot messages, thread broadcasts, etc.
    subtype = event.get("subtype")
    channel = event.get("channel")
    user = event.get("user")
    text = event.get("text", "")
    ts = event.get("ts", "")

    SOURCE_CHANNEL_IDS = os.getenv("SOURCE_CHANNEL_IDS", "").split(",")

    if channel not in SOURCE_CHANNEL_IDS:
        return Response(status=200)

    if subtype is not None:
        return Response(status=200)
    if BOT_USER_ID and user == BOT_USER_ID:
        return Response(status=200)

    # Translate only if Norwegian
    result = detect_and_translate(text)
    if not result:
        print("EVENT PAYLOAD:", json.dumps(event, indent=2), flush=True)
        print("LANG DETECT RESULT:", translator.detect(text), flush=True)
        return Response(status=200)

    src_lang, translated = result

    # Context
    source_name = get_channel_name(client, SOURCE_CHANNEL_ID)
    permalink = get_permalink(client, SOURCE_CHANNEL_ID, ts)

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

    try:
        client.chat_postMessage(
            channel=TARGET_CHANNEL_ID,
            text=f"Translated from #{source_name}: {translated}",
            blocks=blocks,
        )
    except SlackApiError as e:
        print(f"Failed to post translation: {e.response.get('error')}")

    


    return Response(status=200)

@app.get("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    # Local dev; Slack will reach this via ngrok later
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))

#test