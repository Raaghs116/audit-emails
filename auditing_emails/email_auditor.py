"""
Core email auditing logic – shared by CLI and Streamlit app.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict, Callable

import pandas as pd
import tldextract
import dns.resolver
from email_validator import validate_email, EmailNotValidError

from .rules import AuditConfig, is_role_account

logger = logging.getLogger(__name__)


def detect_email_column(df: pd.DataFrame) -> Optional[str]:
    """Try to detect the email column if the user didn't specify one."""
    preferred_names = ["email", "e-mail", "mail", "email_address", "e_mail"]
    cols_lower = {c.lower(): c for c in df.columns}

    for name in preferred_names:
        if name in cols_lower:
            return cols_lower[name]

    if not df.empty:
        sample = df.iloc[0]
        for col in df.columns:
            val = str(sample[col])
            if "@" in val and "." in val:
                return col

    return None


def extract_domain(email: str) -> Optional[str]:
    if "@" not in email:
        return None
    try:
        _, domain = email.rsplit("@", 1)
        domain = domain.strip().lower()
        if not domain:
            return None
        return domain
    except Exception:
        return None


def check_mx(domain: str, timeout: float = 3.0) -> bool:
    """Check if the domain has at least one MX record."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return len(answers) > 0
    except Exception:
        return False


@dataclass
class EmailAuditResult:
    email: str
    reason: str
    keep: bool
    detail: Dict[str, str]


class EmailAuditor:
    def __init__(self, config: AuditConfig):
        self.config = config

    def audit_dataframe(
        self,
        df: pd.DataFrame,
        email_column: Optional[str] = None,
        suppression_emails: Optional[set] = None,
        suppression_domains: Optional[set] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Run full audit on the DataFrame."""
        if suppression_emails is None:
            suppression_emails = set()
        if suppression_domains is None:
            suppression_domains = set()

        if email_column is None:
            email_column = detect_email_column(df)
            if email_column is None:
                raise ValueError("Could not detect email column automatically. Please specify one explicitly.")

        logger.info("Using email column: %s", email_column)

        df = df.copy()
        df[email_column] = df[email_column].astype(str).str.strip()

        seen_emails = set()
        audit_rows: List[Dict[str, str]] = []
        keep_indices = []

        total_rows = len(df)
        processed = 0

        for idx, row in df.iterrows():
            processed += 1
            if progress_callback is not None:
                try:
                    progress_callback(processed, total_rows)
                except Exception:
                    pass

            raw_email = row[email_column]
            normalized_email = raw_email.strip().lower()
            detail = {
                "normalized_email": normalized_email,
                "syntax_valid": "False",
                "has_mx": "Unknown",
                "is_duplicate": "False",
                "is_disposable": "False",
                "is_freemail": "False",
                "is_role_account": "False",
                "in_suppression": "False",
                "in_blocklist": "False",
            }

            if not normalized_email or "@" not in normalized_email:
                audit_rows.append({
                    "email": raw_email,
                    "keep": False,
                    "reason": "invalid_syntax",
                    **detail
                })
                continue

            try:
                v = validate_email(normalized_email, check_deliverability=False)
                normalized_email = v.normalized
                detail["syntax_valid"] = "True"
            except EmailNotValidError as e:
                audit_rows.append({
                    "email": raw_email,
                    "keep": False,
                    "reason": f"invalid_syntax:{str(e)}",
                    **detail
                })
                continue

            if self.config.dedupe and normalized_email in seen_emails:
                detail["is_duplicate"] = "True"
                audit_rows.append({
                    "email": normalized_email,
                    "keep": False,
                    "reason": "duplicate",
                    **detail
                })
                continue
            seen_emails.add(normalized_email)

            domain = extract_domain(normalized_email)
            if not domain:
                audit_rows.append({
                    "email": normalized_email,
                    "keep": False,
                    "reason": "invalid_domain",
                    **detail
                })
                continue

            detail["domain"] = domain

            ext = tldextract.extract(domain)
            registered_domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
            detail["registered_domain"] = registered_domain or domain

            if registered_domain in self.config.blocklist_domains:
                detail["in_blocklist"] = "True"
                audit_rows.append({
                    "email": normalized_email,
                    "keep": False,
                    "reason": "blocklist_domain",
                    **detail
                })
                continue

            if normalized_email in suppression_emails or registered_domain in suppression_domains:
                detail["in_suppression"] = "True"
                audit_rows.append({
                    "email": normalized_email,
                    "keep": False,
                    "reason": "suppression_list",
                    **detail
                })
                continue

            if registered_domain in self.config.disposable_domains:
                detail["is_disposable"] = "True"
                if self.config.drop_disposable:
                    audit_rows.append({
                        "email": normalized_email,
                        "keep": False,
                        "reason": "disposable_domain",
                        **detail
                    })
                    continue

            if registered_domain in self.config.freemail_domains:
                detail["is_freemail"] = "True"
                if self.config.drop_freemail:
                    audit_rows.append({
                        "email": normalized_email,
                        "keep": False,
                        "reason": "freemail_domain",
                        **detail
                    })
                    continue

            local_part = normalized_email.split("@", 1)[0]
            if is_role_account(local_part, self.config.role_prefixes):
                detail["is_role_account"] = "True"
                if self.config.drop_role_accounts:
                    audit_rows.append({
                        "email": normalized_email,
                        "keep": False,
                        "reason": "role_account",
                        **detail
                    })
                    continue

            if self.config.require_mx:
                has_mx = check_mx(domain)
                detail["has_mx"] = str(bool(has_mx))
                if not has_mx:
                    audit_rows.append({
                        "email": normalized_email,
                        "keep": False,
                        "reason": "no_mx_record",
                        **detail
                    })
                    continue

            keep_indices.append(idx)
            audit_rows.append({
                "email": normalized_email,
                "keep": True,
                "reason": "ok",
                **detail
            })

        cleaned_df = df.loc[keep_indices].reset_index(drop=True)
        report_df = pd.DataFrame(audit_rows)

        return cleaned_df, report_df
