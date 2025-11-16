"""CLI entrypoint for the Auditing Emails project."""

import argparse
import logging
from pathlib import Path

import pandas as pd

from auditing_emails.rules import AuditConfig
from auditing_emails.email_auditor import EmailAuditor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("audit_cli")


def load_list_file(path: Path):
    items = set()
    if not path.exists():
        return items
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.add(line.lower())
    return items


def load_suppression(path: Path):
    emails = set()
    domains = set()
    if not path.exists():
        logger.warning("Suppression file %s does not exist, ignoring.", path)
        return emails, domains

    try:
        if path.suffix.lower() == ".csv":
            df = pd.read_csv(path)
            possible_cols = [c for c in df.columns if "email" in c.lower() or "mail" in c.lower()]
            if possible_cols:
                col = possible_cols[0]
            else:
                col = df.columns[0]
            for v in df[col].astype(str):
                v = v.strip().lower()
                if not v:
                    continue
                if "@" in v:
                    emails.add(v)
                else:
                    domains.add(v)
        else:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    v = line.strip().lower()
                    if not v or v.startswith("#"):
                        continue
                    if "@" in v:
                        emails.add(v)
                    else:
                        domains.add(v)
    except Exception as e:
        logger.error("Failed to load suppression file %s: %s", path, e)

    return emails, domains


def main():
    parser = argparse.ArgumentParser(description="Audit and clean email CSV files.")
    parser.add_argument("--input", "-i", required=True, help="Input CSV file with contacts.")
    parser.add_argument("--output", "-o", required=True, help="Output CSV file for cleaned emails.")
    parser.add_argument("--report", "-r", help="Optional CSV report of every email and reason.")

    parser.add_argument("--email-column", help="Name of the email column. If omitted, auto-detect.")
    parser.add_argument("--suppression", help="Path to suppression list (CSV or TXT).")

    parser.add_argument("--require-mx", dest="require_mx", action="store_true", help="Require MX records (default).")
    parser.add_argument("--no-mx", dest="require_mx", action="store_false", help="Do NOT check MX records.")
    parser.set_defaults(require_mx=True)

    parser.add_argument("--dedupe", dest="dedupe", action="store_true", help="Remove duplicate emails (default).")
    parser.add_argument("--no-dedupe", dest="dedupe", action="store_false", help="Do NOT deduplicate.")
    parser.set_defaults(dedupe=True)

    parser.add_argument("--drop-disposable", dest="drop_disposable", action="store_true",
                        help="Drop disposable/temporary domains (default).")
    parser.add_argument("--keep-disposable", dest="drop_disposable", action="store_false",
                        help="Keep disposable/temporary domains.")
    parser.set_defaults(drop_disposable=True)

    parser.add_argument("--drop-freemail", dest="drop_freemail", action="store_true",
                        help="Drop free email providers (gmail.com, outlook.com, etc.).")
    parser.add_argument("--keep-freemail", dest="drop_freemail", action="store_false",
                        help="Keep free email providers (default).")
    parser.set_defaults(drop_freemail=False)

    parser.add_argument("--drop-role", dest="drop_role", action="store_true",
                        help="Drop role accounts (info@, support@, etc.).")
    parser.add_argument("--keep-role", dest="drop_role", action="store_false",
                        help="Keep role accounts (default).")
    parser.set_defaults(drop_role=False)

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    report_path = Path(args.report) if args.report else None

    if not input_path.exists():
        raise SystemExit(f"Input file {input_path} does not exist.")

    logger.info("Loading input CSV: %s", input_path)
    df = pd.read_csv(input_path, dtype=str, keep_default_na=False, na_values=[], on_bad_lines="skip")

    data_dir = Path(__file__).resolve().parents[1] / "data"
    freemail = load_list_file(data_dir / "freemail_domains.txt")
    disposable = load_list_file(data_dir / "disposable_domains.txt")
    blocklist = load_list_file(data_dir / "blocklist_domains.txt")

    config = AuditConfig(
        require_mx=args.require_mx,
        drop_disposable=args.drop_disposable,
        drop_freemail=args.drop_freemail,
        drop_role_accounts=args.drop_role,
        dedupe=args.dedupe,
        freemail_domains=freemail,
        disposable_domains=disposable,
        blocklist_domains=blocklist,
    )

    auditor = EmailAuditor(config=config)

    if args.suppression:
        suppression_emails, suppression_domains = load_suppression(Path(args.suppression))
    else:
        suppression_emails, suppression_domains = set(), set()

    cleaned_df, report_df = auditor.audit_dataframe(
        df,
        email_column=args.email_column,
        suppression_emails=suppression_emails,
        suppression_domains=suppression_domains,
        progress_callback=None,
    )

    logger.info("Writing cleaned output: %s (rows: %d)", output_path, len(cleaned_df))
    cleaned_df.to_csv(output_path, index=False)

    if report_path:
        logger.info("Writing audit report: %s (rows: %d)", report_path, len(report_df))
        report_df.to_csv(report_path, index=False)

    logger.info("Done.")


if __name__ == "__main__":
    main()
