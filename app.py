import io
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from auditing_emails.rules import AuditConfig
from auditing_emails.email_auditor import EmailAuditor, detect_email_column


st.set_page_config(
    page_title="Auditing Emails – Deliverability Cleaner",
    layout="wide",
)

st.title("📬 Auditing Emails – Deliverability Cleaner")

st.markdown(
    "Upload your CSV file with contacts, configure the deliverability rules, "
    "and download a cleaned email list plus a full audit report."
)


# --- Session state init ---
if "audit_done" not in st.session_state:
    st.session_state.audit_done = False
if "cleaned_df" not in st.session_state:
    st.session_state.cleaned_df = None
if "report_df" not in st.session_state:
    st.session_state.report_df = None
if "metrics" not in st.session_state:
    st.session_state.metrics = None


@st.cache_data
def load_list_file_from_disk(path: Path):
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


def load_suppression_from_upload(file) -> tuple[set, set]:
    """Load suppression from an uploaded file (CSV or TXT). Returns (emails, domains)."""
    if file is None:
        return set(), set()

    emails = set()
    domains = set()
    try:
        name = file.name.lower()
        if name.endswith(".csv"):
            df = pd.read_csv(file)
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
            content = file.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                v = line.strip().lower()
                if not v or v.startswith("#"):
                    continue
                if "@" in v:
                    emails.add(v)
                else:
                    domains.add(v)
    except Exception as e:
        st.warning(f"Failed to parse suppression file: {e}")

    return emails, domains


with st.sidebar:
    st.header("⚙️ Settings")

    st.markdown("**Deliverability rules**")
    require_mx = st.checkbox("Require MX records", value=True,
                             help="Drop domains that do not publish any MX records.")
    drop_disposable = st.checkbox("Drop disposable / temporary email domains", value=True)
    drop_freemail = st.checkbox("Drop freemail providers (gmail.com, outlook.com, etc.)", value=False)
    drop_role = st.checkbox("Drop role accounts (info@, support@, etc.)", value=False)
    dedupe = st.checkbox("Deduplicate emails (case-insensitive)", value=True)

    st.markdown("---")
    st.markdown("**Suppression list**")
    suppression_file = st.file_uploader(
        "Upload suppression list (CSV or TXT)",
        type=["csv", "txt"],
        help="Emails or domains that should always be removed.",
    )

    st.markdown("---")
    st.caption("All logic is local to this app. No data is sent externally.")


uploaded_file = st.file_uploader(
    "Upload contacts CSV",
    type=["csv"],
    help="The file should contain at least one column with email addresses.",
)

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file, dtype=str, keep_default_na=False, na_values=[], on_bad_lines="skip")
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
        st.stop()

    st.subheader("Preview of uploaded data")
    st.dataframe(df.head(20), use_container_width=True)

    if df.empty:
        st.warning("The uploaded CSV appears to be empty.")
        st.stop()

    auto_col = detect_email_column(df)
    st.markdown("### Select email column")
    email_column = st.selectbox(
        "Choose the column that contains email addresses",
        options=list(df.columns),
        index=list(df.columns).index(auto_col) if auto_col in df.columns else 0,
    )
    if auto_col and auto_col != email_column:
        st.info(f"Auto-detected email column was **{auto_col}**, but you overrode it.")

    data_dir = Path(__file__).resolve().parent / "data"
    freemail_domains = load_list_file_from_disk(data_dir / "freemail_domains.txt")
    disposable_domains = load_list_file_from_disk(data_dir / "disposable_domains.txt")
    blocklist_domains = load_list_file_from_disk(data_dir / "blocklist_domains.txt")

    suppression_emails, suppression_domains = load_suppression_from_upload(suppression_file)

    config = AuditConfig(
        require_mx=require_mx,
        drop_disposable=drop_disposable,
        drop_freemail=drop_freemail,
        drop_role_accounts=drop_role,
        dedupe=dedupe,
        freemail_domains=freemail_domains,
        disposable_domains=disposable_domains,
        blocklist_domains=blocklist_domains,
    )

    auditor = EmailAuditor(config=config)

    st.markdown("### Run audit")
    run_button = st.button("🚀 Run email audit")

    if run_button:
        progress_bar = st.progress(0, text="Running audit...")
        status_text = st.empty()

        start_time = time.time()

        def progress_callback(current, total):
            elapsed = time.time() - start_time
            pct = int(current / total * 100) if total else 0
            eps = current / elapsed if elapsed > 0 else 0.0
            remaining = (total - current) / eps if eps > 0 else 0.0
            mins = int(remaining // 60)
            secs = int(remaining % 60)

            progress_bar.progress(pct, text=f"Running audit... {pct}%")
            status_text.markdown(
                f"**Processed:** {current:,}/{total:,} rows · "
                f"**Speed:** {eps:0.1f} emails/s · "
                f"**Est. remaining:** {mins:02d}:{secs:02d} (mm:ss)"
            )

        with st.spinner("Auditing emails..."):
            cleaned_df, report_df = auditor.audit_dataframe(
                df,
                email_column=email_column,
                suppression_emails=suppression_emails,
                suppression_domains=suppression_domains,
                progress_callback=progress_callback,
            )

        total_rows = len(df)
        kept_rows = len(cleaned_df)
        dropped_rows = total_rows - kept_rows
        keep_rate = (kept_rows / total_rows * 100) if total_rows else 0.0

        st.session_state.cleaned_df = cleaned_df
        st.session_state.report_df = report_df
        st.session_state.metrics = {
            "total_rows": total_rows,
            "kept_rows": kept_rows,
            "dropped_rows": dropped_rows,
            "keep_rate": keep_rate,
        }
        st.session_state.audit_done = True

        progress_bar.progress(100, text="Completed.")
        status_text.markdown("✅ Audit completed.")
        st.balloons()


# --- Results rendering (survives reruns) ---
if st.session_state.audit_done and st.session_state.cleaned_df is not None:
    cleaned_df = st.session_state.cleaned_df
    report_df = st.session_state.report_df
    metrics = st.session_state.metrics or {}

    total_rows = metrics.get("total_rows", len(cleaned_df) + (len(report_df) - len(cleaned_df)))
    kept_rows = metrics.get("kept_rows", len(cleaned_df))
    dropped_rows = metrics.get("dropped_rows", total_rows - kept_rows)
    keep_rate = metrics.get("keep_rate", (kept_rows / total_rows * 100) if total_rows else 0.0)

    st.success(f"Audit completed. Kept {kept_rows} rows out of {total_rows}.")

    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    mcol1.metric("Total rows", f"{total_rows:,}")
    mcol2.metric("Kept (deliverable)", f"{kept_rows:,}")
    mcol3.metric("Dropped", f"{dropped_rows:,}")
    mcol4.metric("Keep rate", f"{keep_rate:0.1f}%")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Cleaned emails")
        st.dataframe(cleaned_df.head(50), use_container_width=True)

        cleaned_csv = cleaned_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download cleaned CSV",
            data=cleaned_csv,
            file_name="cleaned_emails.csv",
            mime="text/csv",
        )

    with col2:
        st.markdown("#### Full audit report")
        st.dataframe(report_df.head(50), use_container_width=True)

        report_csv = report_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download audit report CSV",
            data=report_csv,
            file_name="audit_report.csv",
            mime="text/csv",
        )

else:
    st.info("Upload a CSV file and run the audit to see results.")
