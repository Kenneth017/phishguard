import os
import re
import json
from urllib.parse import urlparse
from groq import AsyncGroq
from app.models import AnalyzeRequest, AnalyzeResponse

GROQ_MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = """You are an email security expert. Analyze the email and respond ONLY with valid JSON:
{"is_phishing":bool,"confidence":0.0-1.0,"risk_level":"low"|"medium"|"high"|"critical","reasons":["..."],"recommendation":"..."}

Rules for reasons:
- Be SPECIFIC — name the actual sender, domain, subject, or link you found suspicious or safe
- Each reason should reference concrete evidence from the email (e.g. "Sender 'support@paypa1.com' misspells paypal.com")
- Check: sender domain vs display name, link destinations vs display text, urgency/threats, credential requests
- For safe emails: state WHY it looks legitimate (e.g. "Sender domain glassdoor.com matches company name in display")
- List 3-5 specific findings, not generic statements
- Keep each reason under 15 words"""

_SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".online", ".site"}
_BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook",
           "instagram", "chase", "wellsfargo", "citibank", "usps", "fedex", "dhl", "dropbox", "bdo", "bpi", "metrobank"]
_URGENCY = ["immediately", "urgent", "suspended", "verify now", "confirm now",
            "expire", "action required", "your account has been", "unusual activity",
            "click here to verify", "update your information"]


def quick_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Rule-based scan — returns in <100ms."""
    parsed = urlparse(req.url)
    domain = parsed.netloc.lower().lstrip("www.")
    score = 0
    reasons = []

    if parsed.scheme == "http":
        score += 1
        reasons.append("No HTTPS encryption")

    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        score += 3
        reasons.append("IP address used instead of domain name")

    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 2
            reasons.append(f"Suspicious TLD ({tld})")
            break

    for brand in _BRANDS:
        if brand in domain:
            root = domain.split(".")[-2] if domain.count(".") >= 1 else domain
            if root != brand:
                score += 3
                reasons.append(f"Brand name '{brand}' spoofed in domain")
                break

    if domain.split(".")[0].count("-") >= 2:
        score += 1
        reasons.append("Multiple hyphens in domain")

    # Sender domain mismatch
    if req.sender:
        sender_lower = req.sender.lower()
        for brand in _BRANDS:
            if brand in sender_lower:
                sender_domain = re.search(r"@([\w.-]+)", sender_lower)
                if sender_domain and brand not in sender_domain.group(1):
                    score += 3
                    reasons.append(f"Sender claims to be '{brand}' but email domain doesn't match")
                    break

    if req.body_text:
        text = req.body_text.lower()
        for phrase in _URGENCY:
            if phrase in text:
                score += 1
                reasons.append("Urgency/scare language detected")
                break

    # Link display text vs href mismatch
    if req.links:
        for link in req.links[:10]:
            if "→" in link:
                display, href = link.split("→", 1)
                display = display.strip().lower()
                href = href.strip().lower()
                for brand in _BRANDS:
                    if brand in display and brand not in href:
                        score += 2
                        reasons.append(f"Link text mentions '{brand}' but URL goes elsewhere")
                        break

    if score == 0:
        return AnalyzeResponse(is_phishing=False, confidence=0.75, risk_level="low",
            reasons=["No obvious phishing indicators detected"],
            recommendation="Email appears safe based on quick scan.", model_used="rules")
    elif score <= 2:
        return AnalyzeResponse(is_phishing=False, confidence=0.55, risk_level="medium",
            reasons=reasons, recommendation="Some suspicious signals. Proceed with caution.", model_used="rules")
    elif score <= 4:
        return AnalyzeResponse(is_phishing=True, confidence=0.75, risk_level="high",
            reasons=reasons, recommendation="Multiple phishing indicators. Do not click links or enter credentials.", model_used="rules")
    else:
        return AnalyzeResponse(is_phishing=True, confidence=0.92, risk_level="critical",
            reasons=reasons, recommendation="Strong phishing indicators. Do not interact. Report this email.", model_used="rules")


def build_prompt(req: AnalyzeRequest) -> str:
    parts = [f"URL/Source: {req.url}"]
    if req.sender:
        parts.append(f"Sender: {req.sender}")
    if req.subject:
        parts.append(f"Subject: {req.subject}")
    if req.body_text:
        parts.append(f"Body:\n{req.body_text[:2000]}")
    if req.links:
        parts.append(f"Links (display → href):\n" + "\n".join(req.links[:20]))
    return "\n\n".join(parts)


async def ai_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """AI analysis via Groq — ~1s response time."""
    client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
    response = await client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(req)},
        ],
        temperature=0.1,
        max_tokens=512,
        response_format={"type": "json_object"},
    )
    result = json.loads(response.choices[0].message.content)
    return AnalyzeResponse(**result, model_used=f"groq/{GROQ_MODEL}")
