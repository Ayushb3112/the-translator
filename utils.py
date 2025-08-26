import html
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

_channel_cache = {}

def get_channel_name(client: WebClient, channel_id: str) -> str:
    if channel_id in _channel_cache:
        return _channel_cache[channel_id]
    try:
        info = client.conversations_info(channel=channel_id)
        name = info["channel"]["name"]
        _channel_cache[channel_id] = name
        return name
    except SlackApiError:
        return channel_id

def get_permalink(client: WebClient, channel_id: str, ts: str) -> str:
    try:
        res = client.chat_getPermalink(channel=channel_id, message_ts=ts)
        return res["permalink"]
    except SlackApiError:
        return ""

def escape_md(text: str) -> str:
    # Slack mrkdwn is fairly permissive; basic HTML escape to avoid odd cases
    return html.escape(text or "")
