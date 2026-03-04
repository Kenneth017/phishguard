from pydantic import BaseModel
from typing import Optional


class AnalyzeRequest(BaseModel):
    url: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    body_text: Optional[str] = None
    links: Optional[list[str]] = None  # "display text → href"


class AnalyzeResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_level: str        # low | medium | high | critical
    reasons: list[str]
    recommendation: str
    model_used: str


class ReportRequest(BaseModel):
    url: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    body_text: Optional[str] = None
    links: Optional[list[str]] = None
    analysis: Optional[dict] = None   # the AnalyzeResponse that triggered the report
    reporter_email: Optional[str] = None
