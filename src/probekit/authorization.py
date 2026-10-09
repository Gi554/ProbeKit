"""Read-only authorization checks against an explicit policy manifest."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from .models import Finding, Report
from .compare import backend, similarity
from .render import save_reports
from .target import Target


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def pointer(value, path):
    if path == "":
        return value
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Un pointeur JSON doit commencer par /.")
    for part in path[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def matches(value, markers):
    try:
        return all(pointer(value, key) == expected for key, expected in markers.items())
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def validate(manifest):
    target = Target.parse(manifest["origin"])
    parsed = urlsplit(target.url)
    if parsed.path not in ("", "/") or parsed.query:
        raise ValueError("origin doit contenir uniquement le protocole, l'hôte et le port.")
    prefix = manifest.get("prefix", "/api")
    if not isinstance(prefix, str) or not prefix.startswith("/") or ".." in prefix or "?" in prefix:
        raise ValueError("Préfixe de périmètre invalide.")
    accounts = manifest["accounts"]
    cases = manifest["cases"]
    if not isinstance(accounts, dict) or not isinstance(cases, list):
        raise ValueError("accounts doit être un objet et cases une liste.")
    if not 1 <= len(accounts) <= 10 or not 1 <= len(cases) <= 100:
        raise ValueError("Limites : 10 comptes et 100 scénarios.")
    identity_keys = set()
    identity_values = set()
    for name, account in accounts.items():
        if not isinstance(name, str) or not isinstance(account, dict):
            raise ValueError("Compte invalide.")
        if not account.get("anonymous"):
            if not account.get("identity") or not account.get("headers_env"):
                raise ValueError("Chaque compte authentifié exige identity et headers_env.")
            identity = account["identity"]
            if not isinstance(identity, dict) or len(identity) != 1:
                raise ValueError("identity doit désigner un seul champ identifiant le principal.")
            key, value = next(iter(identity.items()))
            if not isinstance(key, str) or not key.startswith("/") or not isinstance(value, (str, int)) or isinstance(value, bool):
                raise ValueError("Identifiant de principal invalide.")
            identity_keys.add(key)
            fingerprint = json.dumps(value)
            if fingerprint in identity_values:
                raise ValueError("Les identités des comptes doivent être distinctes.")
            identity_values.add(fingerprint)
        elif account.get("headers_env"):
            raise ValueError("Un compte anonyme ne peut pas fournir des identifiants.")
        for header, variable in account.get("headers_env", {}).items():
            if header.lower() not in ("authorization", "cookie", "x-api-key") or not isinstance(variable, str):
                raise ValueError("En-tête d'authentification invalide.")
    if len(identity_keys) > 1:
        raise ValueError("Tous les comptes doivent utiliser le même pointeur d'identité.")
    for case in cases:
        if not case.get("markers") or not case.get("allowed") or not case.get("denied"):
            raise ValueError("Chaque scénario exige markers, allowed et denied.")
        names = case["allowed"] + case["denied"]
        if len(names) != len(set(names)) or any(name not in accounts for name in names):
            raise ValueError("Comptes du scénario invalides ou dupliqués.")
        for key in case["markers"]:
            if not key.startswith("/"):
                raise ValueError("Pointeur JSON invalide.")
    return target, prefix.rstrip("/")


def audit_authorization(manifest, timeout=5):
    target, prefix = validate(manifest)
    report = Report(target.url)
    report.metrics["authorization"] = {"identities": [], "cases": [], "comparison_backend": backend()}
    matrix = report.metrics["authorization"]
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    credentials = {}
    valid = set()
    principals = set()

    def request(path, name):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Chemin relatif au périmètre requis.")
        url = urljoin(target.url, path)
        destination = Target.parse(url)
        raw_path = urlsplit(url).path
        if not target.accepts_redirect(url) or not (raw_path == prefix or raw_path.startswith(prefix + "/")):
            raise ValueError("Requête hors périmètre.")
        if any(part in (".", "..") for part in raw_path.split("/")) or "%" in raw_path or "\\" in raw_path:
            raise ValueError("Chemin ambigu refusé.")
        headers = credentials[name]
        if headers and destination.scheme != "https":
            try:
                loopback = ipaddress.ip_address(destination.host).is_loopback
            except ValueError:
                loopback = destination.host == "localhost"
            if not loopback:
                raise ValueError("Les identifiants exigent HTTPS hors laboratoire local.")
        req = urllib.request.Request(url, headers={"Accept": "application/json", **headers}, method="GET")
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("Réponse supérieure à 1 Mio.")
            status = response.code
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            value = None
        return status, value, hashlib.sha256(body).hexdigest()

    for name, account in manifest["accounts"].items():
        credentials[name] = {}
        try:
            if account.get("anonymous"):
                valid.add(name)
                continue
            for header, variable in account["headers_env"].items():
                value = os.environ.get(variable)
                if not value or "\r" in value or "\n" in value:
                    raise ValueError("Variable d'authentification absente ou invalide.")
                credentials[name][header] = value
            status, value, _ = request(manifest.get("identity_path", "/api/me"), name)
            identity = account["identity"]
            fingerprint = json.dumps(identity, sort_keys=True)
            if status != 200 or not matches(value, identity) or fingerprint in principals:
                raise ValueError("Identité non vérifiée ou compte non distinct.")
            principals.add(fingerprint)
            valid.add(name)
            matrix["identities"].append({"account": name, "verified": True})
        except Exception:
            matrix["identities"].append({"account": name, "verified": False})
            report.errors.append(f"Identité indisponible : {name}.")

    for case in manifest["cases"]:
        result = {"name": case.get("name", case["path"]), "responses": [], "outcome": "inconclusive"}
        matrix["cases"].append(result)
        baseline = False
        baseline_body = None
        violated = False
        inconclusive = False
        for name in case["allowed"] + case["denied"]:
            if name not in valid:
                inconclusive = True
                continue
            try:
                status, value, digest = request(case["path"], name)
                protected = matches(value, case["markers"])
                canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                expected = "allowed" if name in case["allowed"] else "denied"
                result["responses"].append({"account": name, "expected": expected, "status": status,
                                            "protected_markers_match": protected, "sha256": digest})
                if baseline_body is not None:
                    result["responses"][-1]["similarity_to_baseline"] = similarity(baseline_body, canonical)
                if expected == "allowed":
                    baseline |= status == 200 and protected
                    if status == 200 and protected:
                        baseline_body = canonical
                    inconclusive |= not (status == 200 and protected)
                elif 200 <= status < 300 and protected:
                    violated = True
                elif status not in (401, 403, 404):
                    inconclusive = True
            except Exception:
                inconclusive = True
                report.errors.append(f"Collecte impossible : {result['name']} / {name}.")
        if baseline and violated:
            result["outcome"] = "violation"
            report.findings.append(Finding("API-AUTHZ", "high", "Accès contraire à la politique déclarée",
                f"Scénario {result['name']} : ressource protégée retrouvée par un compte interdit ; baseline autorisée vérifiée.",
                "Contrôler côté serveur les permissions du compte sur chaque ressource."))
        elif baseline and not inconclusive:
            result["outcome"] = "passed"
        else:
            report.errors.append(f"Scénario non concluant : {result['name']}.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Vérification GET des autorisations API déclarées.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/authorization"))
    args = parser.parse_args(argv)
    try:
        if args.manifest.stat().st_size > 131072:
            raise ValueError("Manifest supérieur à 128 Kio.")
        report = audit_authorization(json.loads(args.manifest.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.error(str(error))
    save_reports(report, args.output)
    print(f"{len(report.findings)} violations · {len(report.errors)} erreurs ou scénarios non concluants")
    return 1 if report.errors or report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
