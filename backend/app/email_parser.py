from __future__ import annotations

from email import policy
from email.parser import Parser
from html.parser import HTMLParser
from typing import Any


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def html_to_text(value: str) -> str:
    parser = _HTMLText()
    parser.feed(value)
    return " ".join(parser.parts)


def parse_raw_email(raw_email: str) -> dict[str, Any]:
    message = Parser(policy=policy.default).parsestr(raw_email)
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            content = part.get_payload(decode=True) or b""
            content = content.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            plain_parts.append(str(content))
        else:
            html_parts.append(str(content))

    body_parts = plain_parts or [html_to_text(value) for value in html_parts]
    return {
        "subject": str(message.get("subject", "")),
        "sender": str(message.get("from", "")),
        "reply_to": str(message.get("reply-to", "")),
        "body": "\n".join(body_parts),
        "headers": message,
    }
