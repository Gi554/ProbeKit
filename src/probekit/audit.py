from email.message import Message
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .checks import cookie_findings, header_findings
from .models import Finding, Report
from .target import Target


class ScopeRedirect(HTTPRedirectHandler):
    def __init__(self, target: Target):
        super().__init__()
        self.target = target

    def redirect_request(self, request, response, code, message, headers, new_url):
        if not self.target.accepts_redirect(new_url):
            raise HTTPError(request.full_url, code, "Redirection hors du périmètre de la cible", headers, None)
        return super().redirect_request(request, response, code, message, headers, new_url)


def audit(target: Target, timeout: float = 5.0) -> Report:
    report = Report(target.url)
    started = time.monotonic()
    if target.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target.host, target.port), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=target.host) as secure:
                    report.metrics["tls_version"] = secure.version()
                    report.metrics["tls_cipher"] = secure.cipher()[0]
                    certificate = secure.getpeercert()
                    if "notAfter" in certificate:
                        remaining = (ssl.cert_time_to_seconds(certificate["notAfter"]) - time.time()) / 86400
                        report.metrics["certificate_days_remaining"] = round(remaining, 1)
                        if remaining < 30:
                            report.findings.append(Finding(
                                "TLS-EXPIRY", "low", "Certificat proche de son expiration",
                                f"Expiration dans {remaining:.1f} jours.", "Vérifier le renouvellement automatique.",
                            ))
        except ssl.SSLCertVerificationError as error:
            report.findings.append(Finding("TLS-CERT", "medium", "Validation du certificat en échec",
                                          error.verify_message, "Vérifier la chaîne, le nom et les dates du certificat."))
        except (OSError, ssl.SSLError) as error:
            report.errors.append(f"Connexion TLS : {error}")

    request = Request(target.url, headers={"User-Agent": "ProbeKit/0.1 configuration-audit"})
    try:
        response = build_opener(ScopeRedirect(target)).open(request, timeout=timeout)
    except HTTPError as response:
        report.status = response.code
        headers = response.headers or Message()
        if 300 <= response.code < 400:
            report.errors.append("Redirection interrompue ; la destination n'a pas été auditée.")
        response.close()
    except (URLError, OSError, ValueError) as error:
        report.errors.append(f"Requête HTTP : {error}")
        report.metrics["duration_seconds"] = round(time.monotonic() - started, 3)
        return report
    else:
        with response:
            report.status = response.status
            headers = response.headers
    report.findings.extend(header_findings(headers, target.scheme == "https"))
    report.findings.extend(cookie_findings(headers, target.scheme == "https"))
    report.metrics["duration_seconds"] = round(time.monotonic() - started, 3)
    return report
