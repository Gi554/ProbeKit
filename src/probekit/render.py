import html
import json
from pathlib import Path

from .models import Report


def save_reports(report: Report, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "report.json").write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "report.html").write_text(render_html(report), encoding="utf-8")


def render_html(report: Report) -> str:
    escape = html.escape
    rows = "".join(
        f"<tr><td>{escape(item.severity)}</td><td>{escape(item.code)}<br><strong>{escape(item.title)}</strong></td>"
        f"<td>{escape(item.evidence)}</td><td>{escape(item.recommendation)}</td></tr>"
        for item in report.findings
    )
    errors = "".join(f"<li>{escape(error)}</li>" for error in report.errors)
    matrix = escape(json.dumps(report.metrics.get("authorization", {}), ensure_ascii=False, indent=2))
    document = f"""<!doctype html><html lang="fr"><meta charset="utf-8"><title>ProbeKit</title>
<style>body{{font:15px system-ui;margin:40px;color:#20304a;background:#f5f7fb}}table{{border-collapse:collapse;width:100%;background:white}}td,th{{padding:16px;border:1px solid #dce3ef;text-align:left;vertical-align:top}}small{{color:#65738c}}h1{{color:#4967d6}}</style>
<h1>ProbeKit · Audit web</h1><p>{escape(report.target)}</p><small>{escape(report.started_at)} · HTTP {report.status}</small>
<p>Les constats de configuration nécessitent une validation contextuelle. Ce rapport ne certifie pas la sécurité de la cible.</p>
<table><thead><tr><th>Niveau</th><th>Constat</th><th>Preuve</th><th>Recommandation</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Erreurs et limites de collecte</h2><ul>{errors}</ul><h2>Matrice des autorisations</h2><pre>{matrix}</pre></html>"""
    return document
