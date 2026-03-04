from fastapi import APIRouter
from app.models import AnalyzeRequest, AnalyzeResponse
from app.detector import quick_analyze, ai_analyze

router = APIRouter(prefix="/api")


@router.post("/quick-analyze", response_model=AnalyzeResponse)
async def quick_analyze_route(req: AnalyzeRequest):
    return quick_analyze(req)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_route(req: AnalyzeRequest):
    try:
        return await ai_analyze(req)
    except Exception as e:
        print(f"AI analysis failed, falling back to rules: {e}")
        return quick_analyze(req)
