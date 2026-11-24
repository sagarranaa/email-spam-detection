"""Run a local Hugging Face email-spam model against text or an .eml file."""

from __future__ import annotations

import argparse
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


MODEL_ID = "adevferjani/distilbert-spam-ceas08"
MAX_TOKENS = 256


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def strip_html(value: str) -> str:
    parser = _HTMLText()
    parser.feed(value)
    return " ".join(parser.parts)


def normalize_email(subject: str, body: str) -> str:
    """Apply the core text normalization described in the model card."""
    text = f"{subject}\n{body}".lower()
    text = strip_html(text)
    text = re.sub(r"https?://\S+|www\.\S+", " urltoken ", text)
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " emailtoken ", text)
    text = re.sub(r"\d+", " numtoken ", text)
    return re.sub(r"\s+", " ", text).strip()


def read_eml(path: Path) -> tuple[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    subject = str(message.get("subject", ""))
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
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain":
            plain_parts.append(str(content))
        else:
            html_parts.append(str(content))

    body_parts = plain_parts or html_parts
    return subject, "\n".join(body_parts)


def label_names(model: AutoModelForSequenceClassification) -> dict[int, str]:
    return {int(index): str(name) for index, name in model.config.id2label.items()}


def guess_spam_id(labels: dict[int, str]) -> int | None:
    for index, name in labels.items():
        if "spam" in name.casefold():
            return index
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eml", nargs="?", type=Path, help="Path to a saved .eml message")
    parser.add_argument("--subject", default="", help="Email subject (use with --body)")
    parser.add_argument("--body", default="", help="Email body (use with --subject)")
    parser.add_argument(
        "--spam-label-id",
        type=int,
        help="Class index that means spam, if the model uses generic LABEL_n names",
    )
    parser.add_argument("--max-tokens", type=int, default=MAX_TOKENS)
    args = parser.parse_args()

    if args.eml and (args.subject or args.body):
        parser.error("pass either an .eml file or --subject/--body, not both")
    if not args.eml and not (args.subject or args.body):
        parser.error("provide an .eml file or at least one of --subject/--body")
    if args.max_tokens < 1:
        parser.error("--max-tokens must be at least 1")

    subject, body = read_eml(args.eml) if args.eml else (args.subject, args.body)
    text = normalize_email(subject, body)

    print(f"Loading {MODEL_ID} on CPU; the first run downloads the model.")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID).to("cpu")
    model.eval()

    labels = label_names(model)
    print("Model labels:", ", ".join(f"{index}={name}" for index, name in labels.items()))
    encoded = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=args.max_tokens,
    )
    with torch.inference_mode():
        probabilities = torch.softmax(model(**encoded).logits[0], dim=-1).tolist()

    for index, score in enumerate(probabilities):
        print(f"{labels.get(index, f'LABEL_{index}')}: {score:.4f}")

    spam_id = args.spam_label_id if args.spam_label_id is not None else guess_spam_id(labels)
    if spam_id is None:
        print("Spam class is not named in the model config; inspect the labels above, then rerun with --spam-label-id.")
        return 2
    if not 0 <= spam_id < len(probabilities):
        parser.error(f"spam label id must be between 0 and {len(probabilities) - 1}")

    print(f"Spam score (softmax): {probabilities[spam_id]:.4f}")
    print("This is an experimental model score, not a production security decision.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
