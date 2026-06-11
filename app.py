"""
IOC Enrichment Pipeline — Professional Web UI
streamlit run app.py → http://localhost:8501
"""

import streamlit as st
import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import yaml
    from dotenv import load_dotenv
except ImportError:
    st.error("Missing dependencies. Run: pip install -r requirements.txt")
    st.stop()

load_dotenv()

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IOC Enrichment — Threat Intelligence Lookup",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    * { font-family: 'Inter', sans-serif; }

    /* ── Remove Streamlit cruft ── */
    #MainMenu, footer, header { visibility: hidden; }
    .stApp { margin-top: -60px; }

    /* ── Hero ── */
    .brand {
        display: flex; align-items: center; justify-content: center; gap: 12px;
        margin: 60px 0 8px 0;
    }
    .brand-icon {
        width: 42px; height: 42px; background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 11px; display: flex; align-items: center; justify-content: center;
        font-size: 1.3rem; color: white; box-shadow: 0 4px 14px rgba(99,102,241,0.25);
    }
    .brand-title {
        font-size: 1.8rem; font-weight: 800; color: #111827;
        letter-spacing: -0.03em;
    }
    .hero-subtitle {
        text-align: center; font-size: 1.05rem; color: #6b7280; margin-bottom: 32px;
        line-height: 1.5;
    }

    /* ── Search ── */
    .search-wrapper {
        max-width: 640px; margin: 0 auto; position: relative;
    }
    .search-box {
        width: 100%; padding: 16px 20px 16px 48px; font-size: 1.05rem;
        border: 2px solid #e5e7eb; border-radius: 14px; outline: none;
        font-family: 'JetBrains Mono', monospace; background: #fafafa;
        transition: all 0.2s; box-sizing: border-box;
    }
    .search-box:focus {
        border-color: #6366f1; background: white; box-shadow: 0 0 0 4px rgba(99,102,241,0.08);
    }
    .search-box::placeholder { color: #c4c4c4; font-family: 'Inter', sans-serif; }
    .search-icon {
        position: absolute; left: 18px; top: 50%; transform: translateY(-50%);
        font-size: 1.1rem; color: #9ca3af; pointer-events: none;
    }

    /* ── Examples ── */
    .examples-row {
        text-align: center; margin-top: 14px;
    }
    .example-chip {
        display: inline-block; padding: 7px 16px; margin: 4px;
        border-radius: 100px; font-size: 0.82rem; font-weight: 500;
        border: 1px solid #e5e7eb; color: #374151; background: white;
        cursor: pointer; transition: all 0.15s;
    }
    .example-chip:hover { background: #f9fafb; border-color: #6366f1; color: #6366f1; }

    /* ── Result card ── */
    .result-card {
        max-width: 640px; margin: 28px auto; border: 1px solid #e5e7eb;
        border-radius: 16px; overflow: hidden; background: white;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .result-top {
        display: flex; justify-content: space-between; align-items: center;
        padding: 22px 26px; border-bottom: 1px solid #f3f4f6;
    }
    .result-type-badge {
        display: inline-block; padding: 3px 10px; border-radius: 6px;
        font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .result-value {
        font-size: 1.25rem; font-weight: 700; color: #111827;
        font-family: 'JetBrains Mono', monospace; margin-top: 6px;
    }
    .result-meta { font-size: 0.78rem; color: #9ca3af; margin-top: 4px; }
    .score-ring {
        width: 72px; height: 72px; border-radius: 50%; display: flex;
        flex-direction: column; align-items: center; justify-content: center;
        font-weight: 800; flex-shrink: 0;
    }
    .score-number { font-size: 1.5rem; line-height: 1; }
    .score-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.7; }
    .score-severity {
        display: inline-block; padding: 2px 10px; border-radius: 4px;
        font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.05em; margin-top: 2px;
    }

    /* ── Data grid ── */
    .data-section { padding: 8px 26px 22px 26px; }
    .data-section-title {
        font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.07em; color: #9ca3af; margin: 16px 0 10px 0;
        padding-bottom: 6px; border-bottom: 1px solid #f9fafb;
    }
    .data-grid {
        display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
        gap: 10px;
    }
    .data-cell {
        padding: 12px 14px; border-radius: 10px; background: #f9fafb;
        border: 1px solid #f3f4f6;
    }
    .data-cell-label {
        font-size: 0.66rem; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.05em; color: #9ca3af; margin-bottom: 3px;
    }
    .data-cell-value {
        font-size: 0.88rem; font-weight: 500; color: #111827;
        word-break: break-all;
    }

    /* ── Tool indicator ── */
    .tool-row {
        display: flex; align-items: center; gap: 8px; padding: 8px 26px;
        font-size: 0.78rem; color: #6b7280; border-top: 1px solid #f9fafb;
    }
    .tool-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
    .tool-dot.ok { background: #10b981; }
    .tool-dot.warn { background: #f59e0b; }
    .tool-dot.err { background: #ef4444; }

    /* ── Empty state ── */
    .empty-state {
        text-align: center; padding: 48px 20px;
    }
    .empty-grid {
        display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
        max-width: 640px; margin: 32px auto 0 auto;
    }
    .empty-card {
        padding: 20px 16px; border-radius: 12px; border: 1px solid #f3f4f6;
        text-align: center; background: #fafafa;
    }
    .empty-card-icon { font-size: 1.5rem; margin-bottom: 8px; }
    .empty-card-title { font-size: 0.82rem; font-weight: 700; color: #111827; margin-bottom: 4px; }
    .empty-card-desc { font-size: 0.72rem; color: #9ca3af; line-height: 1.4; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] { background: #fafafa; border-right: 1px solid #e5e7eb; }

    /* ── Footer ── */
    .footer { text-align: center; font-size: 0.72rem; color: #d1d5db; margin-top: 48px; padding-bottom: 24px; }
</style>
""", unsafe_allow_html=True)

# ── Load backend ─────────────────────────────────────────────────────────────
from pipeline.orchestrator import PipelineOrchestrator
from pipeline.ioc_parser import IOC, IOCParser


@st.cache_resource
def get_orchestrator():
    config = {}
    if os.path.exists("config.yaml"):
        with open("config.yaml") as f:
            config = yaml.safe_load(f) or {}
    return PipelineOrchestrator(config)


orchestrator = get_orchestrator()

# ── Helpers ──────────────────────────────────────────────────────────────────
SEVERITY = {
    "critical": {"color": "#dc2626", "bg": "#fef2f2", "ring": "#fecaca"},
    "high":     {"color": "#ea580c", "bg": "#fff7ed", "ring": "#fed7aa"},
    "medium":   {"color": "#d97706", "bg": "#fffbeb", "ring": "#fde68a"},
    "low":      {"color": "#059669", "bg": "#ecfdf5", "ring": "#a7f3d0"},
    "none":     {"color": "#6b7280", "bg": "#f9fafb", "ring": "#e5e7eb"},
}


def tool_has_key(name: str) -> bool:
    if name == "ipinfo":
        return True  # always available
    return bool(os.getenv(f"{name.upper()}_API_KEY", ""))


def tool_status(name: str) -> str:
    if tool_has_key(name):
        return "ok"
    return "warn"


def build_result(result: dict) -> str:
    ioc = result["ioc"]
    score = result.get("score", {})
    results = result.get("results", {})

    score_val = score.get("score", 0)
    sev = score.get("severity", "none")
    cfg = SEVERITY.get(sev, SEVERITY["none"])
    elapsed = result.get("elapsed", 0)

    # ── Data cells ──
    cells = []

    # ipinfo
    if results.get("ipinfo", {}).get("success"):
        d = results["ipinfo"]["data"]
        loc = ", ".join(filter(None, [d.get("city"), d.get("region"), d.get("country")]))
        risk = "⚠️ High-risk country" if d.get("high_risk_country") else ""
        cells += [
            ("📍 Location", loc or "Unknown"),
            ("🌐 ISP", d.get("isp", "—")),
            ("🔢 ASN", d.get("asn", "—")),
            ("🏳️ Country", f"{d.get('country', '?')} {risk}".strip()),
            ("🕐 Timezone", d.get("timezone", "—")),
            ("🖥️ Hostname", d.get("hostname") or "—"),
        ]

    # abuseipdb
    if results.get("abuseipdb", {}).get("success"):
        d = results["abuseipdb"]["data"]
        cells += [
            ("⚠️ Abuse Score", f"{d.get('abuse_confidence_score', 0)}/100"),
            ("📋 Reports", str(d.get("total_reports", 0))),
            ("👥 Distinct Users", str(d.get("num_distinct_users", 0))),
            ("🏳️ Country", d.get("country_name", "—")),
            ("🏢 ISP", d.get("isp", "—")),
            ("📅 Last Reported", str(d.get("last_reported_at") or "—")),
        ]

    # virustotal
    if results.get("virustotal", {}).get("success"):
        d = results["virustotal"]["data"]
        cells += [
            ("🦠 Malicious", f"{d.get('malicious_detections', 0)}/{d.get('total_engines', 0)}"),
            ("⚠️ Suspicious", str(d.get("suspicious_detections", 0))),
            ("✅ Clean", str(d.get("harmless", 0))),
            ("🏳️ Country", d.get("country", "—")),
            ("🏷️ Reputation", str(d.get("reputation", "—"))),
        ]

    # Build cells HTML
    cells_html = ""
    for label, value in cells:
        cells_html += f"""
        <div class="data-cell">
            <div class="data-cell-label">{label}</div>
            <div class="data-cell-value">{value}</div>
        </div>"""

    # Tool status row
    tool_row = ""
    for name in ["ipinfo", "abuseipdb", "virustotal"]:
        tr = results.get(name, {})
        status = "ok" if tr.get("success") else ("warn" if tr.get("error") else "err")
        tool_row += f'<span class="tool-dot {status}"></span> {name} '

    # Source info
    source = ioc.source
    if ioc.context:
        source += f" — {ioc.context}"
    meta = f"{source} · ⏱ {elapsed:.2f}s"
    if result.get("was_cached"):
        meta += " · ⚡ cached"

    return f"""
    <div class="result-card">
        <div class="result-top">
            <div>
                <span class="result-type-badge" style="background:{cfg['bg']};color:{cfg['color']};border:1px solid {cfg['ring']};">{ioc.type}</span>
                <div class="result-value">{ioc.value}</div>
                <div class="result-meta">{meta}</div>
            </div>
            <div style="text-align:center;">
                <div class="score-ring" style="background:{cfg['bg']};border:3px solid {cfg['ring']};">
                    <div class="score-number" style="color:{cfg['color']};">{score_val:.1f}</div>
                    <div class="score-label">out of 10</div>
                </div>
                <div class="score-severity" style="color:{cfg['color']};background:{cfg['bg']};">{sev}</div>
            </div>
        </div>
        <div class="data-section">
            <div class="data-grid">{cells_html}</div>
            <div class="tool-row">{tool_row}</div>
        </div>
    </div>"""


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ IOC Enrichment")
    st.caption("Instant threat intel for IPs, domains, hashes, and URLs.")

    st.markdown("---")
    st.markdown("#### Data Sources")

    for name, desc in orchestrator.manager.available_tools.items():
        has = tool_has_key(name)
        icon = "●" if has else "○"
        color = "#10b981" if has else "#d1d5db"
        st.markdown(
            f'<span style="color:{color};font-weight:600;">{icon}</span> '
            f'<span style="font-size:0.85rem;font-weight:600;">{name}</span>'
            f'{" <span style=font-size:0.7rem;color:#9ca3af;>— needs key</span>" if not has else ""}',
            unsafe_allow_html=True,
        )
        st.caption(desc[:72] if len(desc) > 72 else desc)

    st.markdown("---")
    st.caption("Pipeline v1.0 · MIT License")

# ── Main ─────────────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([1, 3, 1])
with col2:
    # Brand
    st.markdown("""
    <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div class="brand-title">IOC Enrichment</div>
    </div>
    <div class="hero-subtitle">
        Look up any IP address, domain, file hash, or URL.<br>
        Get geolocation, abuse reports, malware detections, and a risk score — instantly.
    </div>
    """, unsafe_allow_html=True)

    # ── Search input ─────────────────────────────────────────────────────────
    st.markdown('<div class="search-wrapper">', unsafe_allow_html=True)
    ioc_value = st.text_input(
        "search",
        placeholder="Paste an IP, domain, or hash — e.g. 8.8.8.8, evil.com, d41d8cd9...",
        label_visibility="collapsed",
        key="search",
    )
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Buttons ──────────────────────────────────────────────────────────────
    bc1, bc2 = st.columns([1, 1])
    with bc1:
        go = st.button("Look Up", type="primary", use_container_width=True)
    with bc2:
        batch = st.button("Upload File Instead", use_container_width=True)

    # ── Example chips ────────────────────────────────────────────────────────
    st.markdown('<div class="examples-row">', unsafe_allow_html=True)
    st.caption("Try an example:")
    ec1, ec2, ec3, ec4 = st.columns(4)
    examples = {
        "8.8.8.8": ("Google DNS", ec1),
        "5.188.62.38": ("Russian IP", ec2),
        "d41d8cd98f00...": ("Empty hash", ec3),
        "evil.com": ("Domain", ec4),
    }
    clicked = None
    for val, (label, col) in examples.items():
        with col:
            if st.button(val, key=f"ex_{val}", help=label, use_container_width=True):
                clicked = val

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Divider ──────────────────────────────────────────────────────────────
    st.markdown("<hr style='margin:28px 0;border-color:#f3f4f6;'>", unsafe_allow_html=True)

    # ── Execute ──────────────────────────────────────────────────────────────
    if clicked:
        ioc_value = clicked

    if go and ioc_value:
        with st.spinner("Looking up..."):
            try:
                detected = IOCParser.detect_type(ioc_value.strip())
                ioc = IOC(type=detected, value=ioc_value.strip())
                result = orchestrator.process_ioc(ioc)
                st.markdown(build_result(result), unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Could not process this indicator: {e}")

    elif go and not ioc_value:
        st.warning("Type something in the search box above.")

    # ── Empty state ──────────────────────────────────────────────────────────
    if not go and not clicked and not batch:
        st.markdown("""
        <div class="empty-grid">
            <div class="empty-card">
                <div class="empty-card-icon">🌐</div>
                <div class="empty-card-title">IP Address</div>
                <div class="empty-card-desc">Location, ISP, ASN, and whether it's from a risky country.</div>
            </div>
            <div class="empty-card">
                <div class="empty-card-icon">🔗</div>
                <div class="empty-card-title">Domain</div>
                <div class="empty-card-desc">Registrar, DNS records, and malware detections from 70+ engines.</div>
            </div>
            <div class="empty-card">
                <div class="empty-card-icon">🔐</div>
                <div class="empty-card-title">File Hash</div>
                <div class="empty-card-desc">Scan results from VirusTotal — see which AV engines flagged it.</div>
            </div>
            <div class="empty-card">
                <div class="empty-card-icon">🔗</div>
                <div class="empty-card-title">URL</div>
                <div class="empty-card-desc">Check if a link is malicious before you click it.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Batch upload (conditionally shown) ───────────────────────────────────
    if batch:
        st.markdown("---")
        st.markdown("### 📂 Batch Processing")
        st.caption("Upload a CSV file with columns: type, value, source, context")

        st.code("""type,value,source,context
ip,8.8.8.8,alerts,Google DNS
ip,185.130.5.173,threat_intel,C2 server
domain,evilphishing.xyz,phishing,Suspicious""", language="csv")

        uploaded = st.file_uploader("Choose file", type=["csv", "json"], label_visibility="collapsed")
        if uploaded:
            path = f"/tmp/{uploaded.name}"
            with open(path, "wb") as f:
                f.write(uploaded.getbuffer())
            with st.spinner("Processing..."):
                try:
                    batch_results = orchestrator.process_file(path)
                    st.success(f"Done — {len(batch_results)} indicators processed")
                    for r in batch_results:
                        st.markdown(build_result(r), unsafe_allow_html=True)
                except Exception as e:
                    st.error(str(e))

    # ── Footer ───────────────────────────────────────────────────────────────
    st.markdown('<div class="footer">IOC Enrichment Pipeline v1.0</div>', unsafe_allow_html=True)
