import streamlit as st
from falconpy import Alerts
import pandas as pd
import json
import tempfile
import time
from datetime import datetime

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="CrowdStrike Alert Insights", layout="wide")
st.title("🚨 CrowdStrike Alert Insights")

# ---------------- API INPUT ----------------
st.sidebar.header("🔐 CrowdStrike API")

client_id = st.sidebar.text_input("Client ID")
client_secret = st.sidebar.text_input("Client Secret", type="password")

if not client_id or not client_secret:
    st.info("Enter API credentials to continue.")
    st.stop()

falcon = Alerts(client_id=client_id, client_secret=client_secret)

# ---------------- SEVERITY MAP ----------------
SEVERITY_MAP = {
    "Informational": "severity:10",
    "Low": "severity:30",
    "Medium": "severity:50",
    "High": "severity:70",
    "Critical": "severity:90",
}

def map_severity(sev: int) -> str:
    return {
        90: "Critical",
        70: "High",
        50: "Medium",
        30: "Low",
        10: "Informational",
    }.get(sev, f"Other ({sev})")

# ==========================================================
# ALERT FETCH (UI MODE)
# ==========================================================
def get_alerts(limit=1000, severity=None, status=None, product=None, start_ts=None, end_ts=None):
    filters = ["show_in_ui:true"]

    if severity:
        filters.append(SEVERITY_MAP[severity])
    if status:
        filters.append(f"status:'{status}'")
    if product:
        filters.append(f"product:'{product}'")
    if start_ts:
        filters.append(f"created_timestamp:>'{start_ts}'")
    if end_ts:
        filters.append(f"created_timestamp:<'{end_ts}'")

    filter_string = "+".join(filters)

    alerts = []
    after = None
    page_size = 1000

    while len(alerts) < limit:
        body = {
            "limit": page_size,
            "sort": "created_timestamp|desc",
            "filter": filter_string
        }

        if after:
            body["after"] = after

        resp = falcon.get_alerts_combined(body=body)

        if resp["status_code"] != 200:
            raise RuntimeError(resp)

        body_resp = resp["body"]
        resources = body_resp.get("resources", [])
        alerts.extend(resources)

        after = body_resp.get("meta", {}).get("pagination", {}).get("after")
        if not after or not resources:
            break

        time.sleep(0.05)

    for a in alerts:
        a["severity_name"] = map_severity(a.get("severity", 0))

    return alerts[:limit]

# ==========================================================
# BULK EXPORT (STREAMING)
# ==========================================================
def export_alerts_ndjson(output_path, severity=None, status=None, product=None,
                         start_ts=None, end_ts=None, max_records=None):

    filters = ["show_in_ui:true"]

    if severity:
        filters.append(f"severity:{severity}")
    if status:
        filters.append(f"status:'{status}'")
    if product:
        filters.append(f"product:'{product}'")
    if start_ts:
        filters.append(f"created_timestamp:>'{start_ts}'")
    if end_ts:
        filters.append(f"created_timestamp:<'{end_ts}'")

    filter_string = "+".join(filters)

    after = None
    written = 0
    page_size = 1000

    with open(output_path, "w", encoding="utf-8") as f:
        while True:
            body = {
                "limit": page_size,
                "sort": "created_timestamp|desc",
                "filter": filter_string
            }

            if after:
                body["after"] = after

            resp = falcon.get_alerts_combined(body=body)

            if resp["status_code"] != 200:
                raise RuntimeError(resp)

            body_resp = resp["body"]
            alerts = body_resp.get("resources", [])

            if not alerts:
                break

            for alert in alerts:
                f.write(json.dumps(alert) + "\n")
                written += 1
                if max_records and written >= max_records:
                    return written

            after = body_resp.get("meta", {}).get("pagination", {}).get("after")
            if not after:
                break

            time.sleep(0.05)

    return written

# ==========================================================
# SIDEBAR FILTERS
# ==========================================================
st.sidebar.header("Filters")

start_date = st.sidebar.date_input("Start Date", value=None)
end_date = st.sidebar.date_input("End Date", value=None)

severity = st.sidebar.selectbox(
    "Severity",
    ["All", "Informational", "Low", "Medium", "High", "Critical"]
)

status = st.sidebar.selectbox(
    "Status",
    ["All", "new", "in_progress", "reopened", "closed"]
)

product = st.sidebar.selectbox(
    "Product",
    ["All", "cwpp", "data-protection", "epp", "idp",
     "mobile", "ngsiem", "overwatch", "thirdparty", "xdr", "fcs"]
)

limit = st.sidebar.slider("Alerts for UI (≤1000 recommended)", 100, 1000, 300, step=100)

# ---------------- TABS ----------------
overview_tab, export_tab = st.tabs(["📊 Overview", "📤 Bulk Export"])

# ==========================================================
# OVERVIEW TAB
# ==========================================================
with overview_tab:
    if st.sidebar.button("🔍 Fetch Alerts"):

        start_ts = f"{start_date}T00:00:00Z" if start_date else None
        end_ts = f"{end_date}T23:59:59Z" if end_date else None

        with st.spinner("Fetching alerts..."):
            alerts = get_alerts(
                limit=limit,
                severity=None if severity == "All" else severity,
                status=None if status == "All" else status,
                product=None if product == "All" else product,
                start_ts=start_ts,
                end_ts=end_ts
            )

        if not alerts:
            st.warning("No alerts found.")
            st.stop()

        st.success(f"Retrieved {len(alerts)} alerts")

        df = pd.DataFrame(alerts)

        for col in ["severity_name", "status", "product"]:
            if col not in df.columns:
                df[col] = "Unknown"

        c1, c2, c3 = st.columns(3)
        c1.bar_chart(df["severity_name"].value_counts())
        c2.bar_chart(df["status"].value_counts())
        c3.bar_chart(df["product"].value_counts())

        st.subheader("Alert Details")
        for a in alerts:
            title = f"{a.get('severity_name')} | {a.get('status')} | {a.get('product')}"
            with st.expander(title):
                st.json(a)

# ==========================================================
# BULK EXPORT TAB
# ==========================================================
with export_tab:

    st.warning("Streams alerts directly to file. Safe for 100k+ records.")

    exp_sev = st.selectbox("Severity (optional)", ["All", "10", "30", "50", "70", "90"])
    exp_status = st.selectbox("Status (optional)", ["All", "new", "in_progress", "reopened", "closed"])
    exp_product = st.selectbox("Product (optional)",
                               ["All", "cwpp", "epp", "xdr", "ngsiem", "idp", "thirdparty", "fcs"])
    max_records = st.number_input("Max records (0 = unlimited)", min_value=0, value=0)

    if st.button("🚀 Start Export"):

        if not start_date or not end_date:
            st.error("Start and End date required.")
            st.stop()

        start_ts = f"{start_date}T00:00:00Z"
        end_ts = f"{end_date}T23:59:59Z"

        with st.spinner("Exporting alerts..."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".ndjson") as tmp:
                count = export_alerts_ndjson(
                    output_path=tmp.name,
                    severity=None if exp_sev == "All" else exp_sev,
                    status=None if exp_status == "All" else exp_status,
                    product=None if exp_product == "All" else exp_product,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    max_records=None if max_records == 0 else max_records
                )

        st.success(f"Exported {count:,} alerts")

        with open(tmp.name, "rb") as f:
            st.download_button(
                "⬇️ Download NDJSON",
                data=f,
                file_name="crowdstrike_alerts.ndjson",
                mime="application/x-ndjson"
            )
