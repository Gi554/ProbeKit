from collections import Counter
import html
import json

from .store import decode_report

STYLE = """
*{box-sizing:border-box}body{margin:0;background:#f3f5fb;color:#223049;font:14px system-ui,sans-serif}
aside{position:fixed;width:220px;height:100vh;background:#17223a;color:#bac4d9;padding:32px 24px}
aside h1{color:white;font-size:27px;margin:0 0 6px}aside small{color:#8e9cba}aside a{display:block;color:#dde5f5;text-decoration:none;margin-top:38px}
aside .foot{position:absolute;bottom:30px;color:#91a0bf;font-size:12px}main{margin-left:220px;padding:36px 40px;max-width:1600px}
h2{font-size:28px;margin:0 0 8px}h3{font-size:17px}.muted{color:#728099}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:26px}
.pill{background:#e7ecff;color:#4e66d8;border-radius:7px;padding:9px 12px;font-size:12px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}
.card,.panel{background:white;border:1px solid #e1e7f1;border-radius:12px;padding:20px}.metric{font-size:30px;font-weight:700;margin:8px 0 0}
.panel{margin-bottom:22px}form{display:flex;gap:12px;flex-wrap:wrap}input{border:1px solid #d9e0ed;border-radius:7px;padding:12px;font:inherit;flex:1;min-width:180px}
input[name=target]{flex:3}textarea{width:100%;min-height:200px;border:1px solid #d9e0ed;border-radius:7px;padding:12px;font:13px monospace}button,.button{background:#526bdf;color:white;border:0;border-radius:7px;padding:12px 16px;font:inherit;text-decoration:none;display:inline-block;cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:15px 12px;border-bottom:1px solid #edf0f6;vertical-align:top}th{font-size:12px;color:#7a879e;font-weight:600;background:#f7f9fc}
a{color:#4d66d6}code{font:12px ui-monospace,monospace}td.target{max-width:450px;overflow-wrap:anywhere}.tag{padding:4px 8px;border-radius:5px;background:#edf1fb;font-size:12px;white-space:nowrap}
.medium{background:#fff1dd;color:#b2731b}.low{background:#e9edff;color:#4f65cc}.info{background:#eaf2f6;color:#577582}.done{color:#159276;background:#e7f7f0}.failed{color:#ba4252;background:#fce9ed}
.high,.violation{background:#fce9ed;color:#ba4252}.passed{color:#159276;background:#e7f7f0}.inconclusive{background:#fff1dd;color:#b2731b}pre{overflow:auto}
.notice{padding:14px;border-radius:7px;background:#eef2fc;color:#5b6a85;margin-top:14px;line-height:1.6}.evidence{max-width:350px;overflow-wrap:anywhere}.empty{text-align:center;padding:44px;color:#8290a6}
@media(max-width:900px){aside{display:none}main{margin:0;padding:24px}.cards{grid-template-columns:repeat(2,1fr)}.table-wrap{overflow:auto}}
"""

# Shared presentation for the local dashboard and audit reports.
STYLE += """
:root{--ink:#182638;--muted:#677589;--line:#e3e8ed;--accent:#147d6e;--surface:#fff}
body{background:#f5f7f8;color:var(--ink);font:14px/1.55 system-ui,sans-serif}
aside{width:230px;background:#13252b;padding:32px 22px;border-right:1px solid #20373c}
aside h1{letter-spacing:-1px;font-size:26px}aside h1:before{content:'P';display:inline-grid;place-items:center;width:32px;height:32px;background:#38b99a;color:#102b28;border-radius:9px;font-size:19px;margin-right:10px}
aside small{font-size:10px;letter-spacing:2px;color:#88a6ac}aside a{padding:11px 14px;border-radius:8px;background:#223a40;margin-top:32px;font-weight:600}aside a:hover{background:#2c4950}aside .foot{line-height:1.8}
main{margin-left:230px;max-width:1550px;padding:34px 42px 60px}header{gap:20px;margin-bottom:28px}h2{font-size:30px;font-weight:650;letter-spacing:-1px}h3{margin:0;font-size:17px;letter-spacing:-.3px}p{margin:8px 0 16px}.muted{color:var(--muted)}
.eyebrow{font-size:10px;font-weight:750;letter-spacing:1.8px;color:var(--accent);margin-bottom:9px}.pill{background:#e8f4ef;color:#257a63;border:1px solid #d2e9de;border-radius:99px;font-size:10px;letter-spacing:1px;white-space:nowrap}.pill:before{content:'●';font-size:8px;margin-right:7px}
.cards{gap:14px;margin:0 0 28px}.card{position:relative;padding:20px 22px;border-radius:10px;box-shadow:0 2px 3px #162b3903}.card .muted{font-size:10px;font-weight:700;letter-spacing:1px}.metric{font-size:34px;font-weight:600;letter-spacing:-1px;line-height:1.3}.card small{color:var(--muted);font-size:11px}
.panel{border-color:var(--line);border-radius:12px;padding:26px;margin-bottom:24px;box-shadow:0 3px 12px #182d3903}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:20px}.section-head p{margin:5px 0 0;color:var(--muted);font-size:12px}.section-number{display:grid;place-items:center;width:35px;height:35px;border:1px solid #dbeae5;background:#f1f8f5;border-radius:9px;color:var(--accent);font-size:13px;font-weight:700;flex:none}.section-title{display:flex;gap:12px}
form{gap:16px;align-items:end}.field{display:flex;flex-direction:column;gap:7px;flex:1;min-width:150px}.field.wide{flex:2}.field.full{flex-basis:100%}label{font-size:12px;font-weight:600;color:#425267}input,textarea{width:100%;min-width:0;background:#fafcfc;border-color:#d9e1e5;padding:12px 13px;color:var(--ink);outline:none;transition:border-color .15s,box-shadow .15s}input::placeholder,textarea::placeholder{color:#8994a1}input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px #147d6e16;background:white}textarea{min-height:180px;resize:vertical;font:12px/1.6 ui-monospace,monospace}button,.button{background:var(--accent);font-size:12px;font-weight:650;border-radius:8px;padding:13px 18px;transition:background .15s;white-space:nowrap}button:hover,.button:hover{background:#106355;color:white}a{color:var(--accent)}a:hover{text-decoration:underline}.button.secondary{background:white;border:1px solid #d9e2e5;color:#41576a}.button.secondary:hover{background:#f1f6f5}a:focus-visible,button:focus-visible,summary:focus-visible{outline:3px solid #38b99a;outline-offset:3px}
.notice{background:#f5f8f8;border:1px solid #e6eded;font-size:11px;color:#657682;line-height:1.7;margin-top:18px;padding:12px 14px;border-radius:8px}.notice strong{color:#405a66}.table-wrap{overflow:auto}table{font-size:12px}td,th{padding:16px 14px}th{background:#f6f9f9;font-size:9px;letter-spacing:.9px;color:#6c7e8b;border-top:1px solid var(--line)}td{border-color:#ecf0f2}tbody tr:hover{background:#fafcfc}tbody tr:last-child td{border-bottom:0}.target a{font-weight:600;text-decoration:none}.tag{display:inline-block;font-size:10px;font-weight:650;border-radius:5px;padding:4px 8px}.partial{background:#fff3de;color:#986315}.queued,.running{background:#eaf0ff;color:#4e68af}.empty{padding:40px}.empty strong{display:block;color:#43586a;font-size:15px;margin-bottom:5px}
details.api summary{cursor:pointer;list-style:none;display:flex;justify-content:space-between;align-items:center;gap:12px}details.api summary::-webkit-details-marker{display:none}summary:after{content:'Configurer +';font-size:11px;color:var(--accent);font-weight:650;white-space:nowrap}details[open] summary:after{content:'Réduire −'}details[open] summary{margin-bottom:22px}.actions{display:flex;gap:10px;flex-wrap:wrap}.scenario{margin-top:22px;border:1px solid var(--line);border-radius:9px;overflow:hidden}.scenario-head{padding:15px 16px;display:flex;justify-content:space-between;gap:12px;align-items:center;background:#fbfcfc}.scenario-head h3{font-size:14px}.evidence{line-height:1.7}.progress{height:5px;background:#e6eff4;border-radius:3px;overflow:hidden;margin-top:5px;width:80px}.progress span{display:block;height:100%;background:#5a9f90}pre{max-width:100%;padding:16px;background:#f6f8f9;border-radius:8px;font-size:11px}.result-lead{display:flex;justify-content:space-between;align-items:center;gap:20px}.result-lead .muted{font-size:12px}.critical{border-top:3px solid #d46670}
@media(min-width:1500px){main{margin-right:auto}}
@media(max-width:1100px){main{padding:28px}aside{width:200px}main{margin-left:200px}form button{width:100%}}
@media(max-width:900px){aside{display:flex;position:static;width:100%;height:auto;padding:16px 24px;align-items:center;justify-content:space-between;border:0}aside h1{font-size:22px;margin:0}aside small,aside .foot{display:none}aside a{margin:0;padding:7px 12px;font-size:11px}main{margin:0;padding:24px}.cards{grid-template-columns:repeat(4,1fr);gap:10px}.card{padding:15px}.metric{font-size:28px}.panel{padding:20px}}
@media(max-width:600px){header{align-items:flex-start}h2{font-size:26px}.pill{font-size:8px;padding:7px 9px}.cards{grid-template-columns:repeat(2,1fr)}main{padding:20px 16px}.field{flex-basis:100%}.panel{padding:18px}.section-head{gap:8px}.section-number{width:30px;height:30px}.result-lead{align-items:flex-start;flex-direction:column}.scenario-head{align-items:flex-start;flex-direction:column}summary:after{font-size:10px}.table-wrap table{min-width:550px}}
"""


def page(body: str, title="Tableau de bord", refresh=False) -> str:
    meta = '<meta http-equiv="refresh" content="3">' if refresh else ""
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{meta}<title>{html.escape(title)} · ProbeKit</title><style>{STYLE}</style></head>
<body><aside><div><h1>ProbeKit</h1><small>ESPACE D'AUDIT</small></div><a href="/">◈ &nbsp; Tableau de bord</a><div class="foot">● &nbsp; Espace local<br>Vos audits restent sur cet appareil.</div></aside><main>{body}</main></body></html>"""


def dashboard(rows: list[dict], token: str) -> str:
    active = sum(row["state"] in {"queued", "running"} for row in rows)
    findings = sum(len(json.loads(row["report"])["findings"]) for row in rows if row["report"])
    projects = len({row["project"] for row in rows})
    cards = "".join(f'<div class="card"><span class="muted">{label}</span><div class="metric">{number}</div></div>'
                    for label, number in (("AUDITS RÉCENTS", len(rows)), ("PROJETS", projects), ("CONSTATS", findings), ("EN COURS", active)))
    table = ""
    labels = {"queued": "En attente", "running": "En cours", "done": "Terminé", "partial": "Collecte partielle", "failed": "Échec"}
    for row in rows:
        count = len(json.loads(row["report"])["findings"]) if row["report"] else "—"
        table += f'<tr><td>{html.escape(row["project"])}</td><td class="target"><a href="/scans/{row["id"]}">{html.escape(row["target"])}</a></td><td><span class="tag {row["state"]}">{labels[row["state"]]}</span></td><td>{count}</td><td>{html.escape(row["created"][:16].replace("T", " "))} UTC</td></tr>'
    if not rows:
        table = '<tr><td colspan="5" class="empty"><strong>Tout commence par un premier audit.</strong>Lancez un contrôle ci-dessus pour retrouver vos résultats ici.</td></tr>'
    body = f"""<header><div><div class="eyebrow">VOTRE ESPACE DE TRAVAIL</div><h2>Vue d'ensemble</h2><div class="muted">Lancez vos contrôles. Examinez les preuves. Suivez les résultats.</div></div><span class="pill">LOCAL</span></header>
<div class="cards">{cards}</div><section class="panel"><div class="section-head"><div class="section-title"><span class="section-number">01</span><div><h3>Audit de configuration</h3><p>Un premier regard sur la configuration de votre site.</p></div></div><span class="tag">WEB</span></div><form method="post" action="/scans"><input type="hidden" name="csrf" value="{html.escape(token, quote=True)}"><div class="field"><label for="web-project">Projet</label><input id="web-project" name="project" placeholder="Ex. Boutique en ligne" maxlength="100" required></div><div class="field wide"><label for="web-target">URL à contrôler</label><input id="web-target" name="target" type="url" placeholder="https://votre-site.example" required></div><button>Lancer l'audit ↗</button></form>
<div class="notice"><strong>Contrôles inclus :</strong> en-têtes HTTP, TLS et attributs des cookies. Les redirections restent sur la même origine. Utilisez une cible dont le test est autorisé.</div></section>
<section class="panel"><details class="api"><summary><div class="section-title"><span class="section-number">02</span><div><h3>Autorisations API</h3><p class="muted" style="font-size:12px;margin:4px 0 0">Comparez les accès de plusieurs comptes de test.</p></div></div></summary><form method="post" action="/scans"><input type="hidden" name="csrf" value="{html.escape(token, quote=True)}"><input type="hidden" name="kind" value="authorization"><div class="field full"><label for="api-project">Projet API</label><input id="api-project" name="project" placeholder="Ex. API de facturation" maxlength="100" required></div><div class="field full"><label for="api-manifest">Scénarios de permissions · manifeste JSON</label><textarea id="api-manifest" name="manifest" placeholder='{{"origin": "https://api.example", "accounts": {{…}}, "cases": […]}}' required maxlength="131072" aria-describedby="manifest-help" spellcheck="false"></textarea></div><button>Vérifier les autorisations ↗</button></form><div class="notice" id="manifest-help">Déclarez les comptes autorisés, les comptes interdits et les marqueurs de ressource. Un exemple est fourni dans <code>examples/authorization.json</code>. Saisissez uniquement les noms des variables d'environnement qui contiennent les identifiants.</div></details></section>
<section class="panel" id="history"><div class="section-head"><div><h3>Derniers audits</h3><p>Votre historique de contrôles et de résultats.</p></div><span class="tag">{len(rows)} / 100</span></div><div class="table-wrap"><table><thead><tr><th>PROJET</th><th>CIBLE</th><th>ÉTAT</th><th>CONSTATS</th><th>DATE</th></tr></thead><tbody>{table}</tbody></table></div></section>"""
    return page(body, refresh=bool(active))


def detail(row: dict) -> str:
    heading = f'<header><div><div class="eyebrow">RÉSULTATS DE L’AUDIT</div><h2>{html.escape(row["project"])}</h2><div class="muted">{html.escape(row["target"])}</div></div><a class="button secondary" href="/">← Historique</a></header>'
    if not row["report"]:
        text = row["error"] or "Travail en cours. Cette page se met à jour automatiquement."
        return page(heading + f'<div class="panel">{html.escape(text)}</div>', "Audit", row["state"] in {"queued", "running"})
    report = decode_report(row["report"])
    counts = Counter(finding.severity for finding in report.findings)
    levels = {"high": "ÉLEVÉ", "medium": "MODÉRÉ", "low": "FAIBLE", "info": "INFORMATION"}
    summary = "".join(f'<div class="card {"critical" if level == "high" and counts[level] else ""}"><span class="muted">{levels[level]}</span><div class="metric">{counts[level]}</div></div>'
                      for level in ("high", "medium", "low", "info"))
    findings = "".join(f'<tr><td><span class="tag {item.severity}">{item.severity}</span></td><td><code>{html.escape(item.code)}</code><br><strong>{html.escape(item.title)}</strong></td><td class="evidence">{html.escape(item.evidence)}</td><td class="evidence">{html.escape(item.recommendation)}</td></tr>' for item in report.findings)
    if not findings:
        findings = '<tr><td colspan="4" class="empty">Aucun constat pour les contrôles exécutés. Cela ne certifie pas la sécurité de la cible.</td></tr>'
    errors = "".join(f'<li>{html.escape(error)}</li>' for error in report.errors)
    metrics = html.escape(json.dumps(report.metrics, ensure_ascii=False, indent=2))
    collection = f'<pre>{metrics}</pre>'
    if authorization := report.metrics.get("authorization"):
        collection = '<p class="muted">Accès attendus et réponses observées, compte par compte. La similarité accompagne les preuves sans confirmer seule une violation.</p>'
        for case in authorization.get("cases", []):
            outcome = case["outcome"]
            label = {"violation": "Violation", "passed": "Contrôle réussi", "inconclusive": "Non concluant"}.get(outcome, outcome)
            collection += f'<div class="scenario"><div class="scenario-head"><h3>{html.escape(case["name"])}</h3><span class="tag {html.escape(outcome)}">{html.escape(label)}</span></div><div class="table-wrap"><table><thead><tr><th>COMPTE</th><th>ACCÈS ATTENDU</th><th>HTTP</th><th>RESSOURCE RETROUVÉE</th><th>SIMILARITÉ</th></tr></thead><tbody>'
            for response in case["responses"]:
                score = response.get("similarity_to_baseline")
                score_text = f'{score:.0%}' if score is not None else "Référence"
                policy = {"allowed": "Autorisé", "denied": "Interdit"}.get(response["expected"], response["expected"])
                collection += f'<tr><td><strong>{html.escape(response["account"])}</strong></td><td>{html.escape(policy)}</td><td><code>{response["status"]}</code></td><td>{"Oui" if response["protected_markers_match"] else "Non"}</td><td>{score_text}</td></tr>'
            collection += '</tbody></table></div></div>'
    body = heading + f'<div class="cards">{summary}</div><section class="panel"><a class="button" href="/scans/{row["id"]}/report.html">Rapport HTML</a> <a class="button" href="/scans/{row["id"]}/report.json">Rapport JSON</a><p class="muted">Les niveaux représentent une priorité de revue, pas une preuve d’exploitation.</p><div class="table-wrap"><table><thead><tr><th>NIVEAU</th><th>CONSTAT</th><th>PREUVE</th><th>RECOMMANDATION</th></tr></thead><tbody>{findings}</tbody></table></div></section><section class="panel"><h3>Collecte</h3><pre>{metrics}</pre><ul>{errors}</ul></section>'
    body = body.replace(f'<pre>{metrics}</pre>', collection).replace('<h3>Collecte</h3>', '<h3>Preuves et scénarios</h3>').replace('class="button" href=', 'class="button secondary" href=')
    return page(body, "Résultat de l'audit")
