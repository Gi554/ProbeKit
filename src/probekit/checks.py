from email.message import Message
from http.cookies import CookieError, SimpleCookie
import re

from .models import Finding


def header_findings(headers: Message, https: bool) -> list[Finding]:
    findings = []

    def add(code, severity, title, evidence, recommendation):
        findings.append(Finding(code, severity, title, evidence, recommendation))

    if https:
        hsts = headers.get("Strict-Transport-Security", "")
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
        if not age or int(age.group(1)) == 0:
            add("WEB-HSTS", "low", "HSTS absent ou désactivé", "Aucune durée HSTS positive.",
                "Évaluer l'activation de HSTS après validation du fonctionnement HTTPS.")
    else:
        add("WEB-HTTP", "medium", "Connexion HTTP non chiffrée", "La cible utilise HTTP.",
            "Fournir HTTPS ; vérifier séparément la redirection du point d'entrée HTTP.")

    csp = headers.get("Content-Security-Policy", "")
    html = "text/html" in headers.get("Content-Type", "").lower()
    if html:
        if not csp:
            add("WEB-CSP", "low", "Politique CSP absente", "Pas de Content-Security-Policy appliquée.",
                "Définir une politique adaptée ; une CSP ne prouve pas l'absence de XSS.")
        framing = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
        xframe = headers.get("X-Frame-Options", "").strip().lower()
        permissive = framing is not None and "*" in framing.group(1).split()
        if permissive or (not framing and xframe not in {"deny", "sameorigin"}):
            add("WEB-FRAME", "low", "Protection contre l'encadrement absente ou permissive",
                "frame-ancestors autorise tout, ou aucune politique d'encadrement valide n'est déclarée.",
                "Déclarer frame-ancestors dans la CSP selon les besoins d'intégration.")
    if headers.get("X-Content-Type-Options", "").strip().lower() != "nosniff":
        add("WEB-NOSNIFF", "low", "Protection nosniff absente", "X-Content-Type-Options n'est pas nosniff.",
            "Définir X-Content-Type-Options: nosniff avec des types MIME corrects.")
    if headers.get("Server") or headers.get("X-Powered-By"):
        add("WEB-BANNER", "info", "Bannière technologique exposée",
            "Présence de Server ou X-Powered-By ; valeurs non conservées.",
            "Limiter les détails inutiles ; ce constat ne démontre pas une vulnérabilité.")
    return findings


def cookie_findings(headers: Message, https: bool) -> list[Finding]:
    findings = []
    for raw in headers.get_all("Set-Cookie", []):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            continue
        for name, morsel in cookie.items():
            missing = []
            if https and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            same_site = morsel["samesite"].lower()
            if same_site not in {"strict", "lax", "none"}:
                missing.append("SameSite explicite valide")
            if same_site == "none" and not morsel["secure"]:
                missing.append("Secure requis avec SameSite=None")
            if missing:
                findings.append(Finding(
                    "WEB-COOKIE", "low", "Attributs de cookie à examiner",
                    f"Cookie {name} : {', '.join(missing)}.",
                    "Vérifier la fonction du cookie : HttpOnly ne convient pas aux cookies lus par JavaScript. "
                    "Appliquer Secure et SameSite selon les besoins. Les valeurs ne sont pas enregistrées.",
                ))
    return findings
