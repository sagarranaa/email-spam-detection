from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

DATA_DIR = Path(os.getenv("APP_DATA_DIR", str(PROJECT_ROOT / "data")))
DATABASE_PATH = Path(os.getenv("APP_DATABASE_PATH", str(DATA_DIR / "scans.sqlite3")))
HF_MODEL_ID = os.getenv("HF_MODEL_ID", "adevferjani/distilbert-spam-ceas08")
HF_SPAM_LABEL_ID = os.getenv("HF_SPAM_LABEL_ID")
