"""Email Analyzer API routes."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ...dependencies import get_current_user, get_email_analyzer

router = APIRouter(prefix="/email", tags=["email"])


class AnalyzeRequest(BaseModel):
    text: str
    urls: list[str] = []


@router.post("/analyze")
async def analyze_content(
    body: AnalyzeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Analyze email/text content for phishing and threats."""
    analyzer = get_email_analyzer()
    return analyzer.analyze_content(body.text, body.urls)


@router.get("/recent")
async def get_recent_analyses(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Get recent email analyses."""
    analyzer = get_email_analyzer()
    return analyzer.get_recent_analyses(limit)
