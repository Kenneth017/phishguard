import os
import json
import aiosmtplib
from email.message import EmailMessage
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.database import get_reports, get_report, update_report, mark_feedback_sent
from app.detector import ai_analyze
from app.models import AnalyzeRequest

router = APIRouter()
templates = Jinja2Templates(directory="templates")

CONSOLE_PASSWORD = os.getenv("CONSOLE_PASSWORD", "admin")


def check_auth(request: Request):
    if request.session.get("authenticated") != True:
        raise HTTPException(status_code=302, headers={"Location": "/console/login"})


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.get("/console/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/console/login")
async def login(request: Request, password: str = Form(...)):
    if password == CONSOLE_PASSWORD:
        request.session["authenticated"] = True
        return RedirectResponse("/console", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid password"})


@router.get("/console/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/console/login", status_code=302)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/console", response_class=HTMLResponse)
async def dashboard(request: Request, status: str = None):
    check_auth(request)
    reports = await get_reports(status)
    for r in reports:
        r["links"] = json.loads(r["links"] or "[]")
        r["analysis"] = json.loads(r["analysis"] or "{}")
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "reports": reports,
        "filter": status,
        "counts": {
            "all": len(await get_reports()),
            "pending": len(await get_reports("pending")),
            "reviewed": len(await get_reports("reviewed")),
            "resolved": len(await get_reports("resolved")),
        }
    })


# ── Report detail + deep analysis ────────────────────────────────────────────

@router.get("/console/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: int):
    check_auth(request)
    report = await get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report["links"] = json.loads(report["links"] or "[]")
    report["analysis"] = json.loads(report["analysis"] or "{}")
    return templates.TemplateResponse("report_detail.html", {"request": request, "report": report})


@router.post("/console/report/{report_id}/deep-analyze")
async def deep_analyze(request: Request, report_id: int):
    check_auth(request)
    report = await get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    req = AnalyzeRequest(
        url=report["url"],
        subject=report["subject"],
        sender=report["sender"],
        body_text=report["body_text"],
        links=json.loads(report["links"] or "[]"),
    )
    result = await ai_analyze(req)
    return result.model_dump()


@router.post("/console/report/{report_id}/update")
async def update_report_route(
    request: Request,
    report_id: int,
    status: str = Form(...),
    admin_notes: str = Form(""),
):
    check_auth(request)
    await update_report(report_id, status, admin_notes)
    return RedirectResponse(f"/console/report/{report_id}", status_code=302)


# ── Send feedback email ───────────────────────────────────────────────────────

@router.post("/console/report/{report_id}/send-feedback")
async def send_feedback(
    request: Request,
    report_id: int,
    feedback_message: str = Form(...),
):
    check_auth(request)
    report = await get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.get("reporter_email"):
        raise HTTPException(status_code=400, detail="No reporter email on file")

    msg = EmailMessage()
    msg["Subject"] = "PhishGuard: Follow-up on your phishing report"
    msg["From"] = os.getenv("SMTP_FROM")
    msg["To"] = report["reporter_email"]
    msg.set_content(feedback_message)

    await aiosmtplib.send(
        msg,
        hostname=os.getenv("SMTP_HOST", "smtp.gmail.com"),
        port=int(os.getenv("SMTP_PORT", "587")),
        username=os.getenv("SMTP_USER"),
        password=os.getenv("SMTP_PASS"),
        start_tls=True,
    )
    await mark_feedback_sent(report_id)
    return RedirectResponse(f"/console/report/{report_id}", status_code=302)
