import argparse
from pathlib import Path

from .audit import audit
from .render import save_reports
from .target import Target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit de configuration web sur une cible autorisée.")
    parser.add_argument("target", help="URL complète de la cible")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 30:
        parser.error("Le délai doit être compris entre 0 et 30 secondes.")
    try:
        target = Target.parse(args.target)
    except ValueError as error:
        parser.error(str(error))
    report = audit(target, args.timeout)
    try:
        save_reports(report, args.output)
    except OSError as error:
        parser.exit(2, f"Impossible d'écrire le rapport : {error}\n")
    print(f"HTTP {report.status} · {len(report.findings)} constats · {len(report.errors)} erreurs")
    print(f"Rapports : {args.output.resolve()}")
    return 1 if report.errors else 0
