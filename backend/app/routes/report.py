from fastapi import APIRouter
from app.models import ReportRequest
from app.database import save_report

router = APIRouter(prefix="/api")


@router.post("/report")
async def report_phishing(req: ReportRequest):
    report_id = await save_report(req.model_dump())
    return {"status": "received", "report_id": report_id}
