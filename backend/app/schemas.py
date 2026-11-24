from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    subject: str = Field(default="", max_length=998)
    sender: str = Field(default="", max_length=512)
    body: str = Field(default="", max_length=200_000)
    raw_email: str | None = Field(default=None, max_length=1_000_000)
    check_dns: bool = False

