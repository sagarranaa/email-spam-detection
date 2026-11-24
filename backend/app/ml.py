from __future__ import annotations

from functools import lru_cache
from typing import Any

from .config import HF_MODEL_ID, HF_SPAM_LABEL_ID


def _normalize_for_model(subject: str, body: str) -> str:
    import re

    from .email_parser import html_to_text

    text = html_to_text(f"{subject}\n{body}").lower()
    text = re.sub(r"https?://\S+|www\.\S+", " urltoken ", text)
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " emailtoken ", text)
    text = re.sub(r"\d+", " numtoken ", text)
    return re.sub(r"\s+", " ", text).strip()


@lru_cache(maxsize=1)
def _load_model() -> tuple[Any, Any]:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(HF_MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(HF_MODEL_ID).to("cpu")
    model.eval()
    return tokenizer, model


def score_email(subject: str, body: str) -> dict[str, Any]:
    try:
        import torch

        tokenizer, model = _load_model()
        encoded = tokenizer(
            _normalize_for_model(subject, body),
            return_tensors="pt",
            truncation=True,
            max_length=256,
        )
        with torch.inference_mode():
            scores = torch.softmax(model(**encoded).logits[0], dim=-1).tolist()
        labels = {int(index): str(label) for index, label in model.config.id2label.items()}
        spam_id: int | None = None
        if HF_SPAM_LABEL_ID is not None:
            spam_id = int(HF_SPAM_LABEL_ID)
        else:
            spam_id = next((index for index, label in labels.items() if "spam" in label.casefold()), None)
        if spam_id is not None and not 0 <= spam_id < len(scores):
            return {"status": "configuration_error", "message": "HF_SPAM_LABEL_ID is outside the model's class range."}
        return {
            "status": "ready" if spam_id is not None else "needs_label_mapping",
            "model": HF_MODEL_ID,
            "labels": labels,
            "scores": {labels.get(index, f"LABEL_{index}"): round(float(value), 4) for index, value in enumerate(scores)},
            "spam_score": round(float(scores[spam_id]), 4) if spam_id is not None else None,
            "note": "Experimental model output; not a production security decision.",
        }
    except Exception:
        return {
            "status": "unavailable",
            "model": HF_MODEL_ID,
            "spam_score": None,
            "message": "Model unavailable. Check the Python dependencies and Hugging Face connectivity, then try again.",
        }
