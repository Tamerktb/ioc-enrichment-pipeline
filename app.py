"""
IOC Enrichment Pipeline — Professional Web UI

Usage:
    streamlit run app.py
    # Opens at http://localhost:8501

Designed to be self-explanatory — no training needed.
"""

import streamlit as st
import sys
import os
import time
from pathlib import Path

# Ensure the project root is on the path
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
    page_title="IOC Enrichment Pipeline — Threat Intelligence Lookup",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS for professional look ─────────────────────────────────────────
st.markdown("""
<style>
    /* Clean typography */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Hero section */
    .hero-title {
        font-size: 2.4rem;
        font-weight: 700;
        margin-bottom: 0.3rem;
        letter-spacing: -0.02em;
    }
    .hero-subtitle {
        font-size: 1.05rem;
        color: #6b7280;
        font-weight: 400;
        margin-bottom: 2rem;
    }

    /* Input row */
    .stTextInput > div > div > input {
        font-size: 1.1rem !important;
        padding: 14px 18px !important;
        border-radius: 10px !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Enrich button */
    div.stButton > button {
        font-size: 1.05rem !important;
        font-weight: 600 !important;
        padding: 12px 28px !important;
        border-radius: 10px !important;
        height: auto !important;
    }

    /* Example chips */
    .chip {
        display: inline-block;
        padding: 6px 14px;
        margin: 0 6px 6px 0;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 500;
        cursor: pointer;
        border: 1px solid #d1d5db;
        background: transparent;
        color: #374151;
        transition: all 0.15s;
    }
    .chip:hover {
        background: #f3f4f6;
        border-color: #9ca3af;
    }

    /* Result card */
    .result-card {
        border: 1px solid #e5e7eb;
        border-radius: 14px;
        padding: 28px 32px;
        margin: 24px 0;
        background: #ffffff;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .result-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 24px;
        padding-bottom: 20px;
        border-bottom: 1px solid #f3f4f6;
    }
    .result-ioc-type {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #6b7280;
        margin-bottom: 4px;
    }
    .result-ioc-value {
        font-size: 1.35rem;
        font-weight: 600;
        color: #111827;
        font-family: 'JetBrains Mono', monospace;
    }
    .result-badge {
        display: inline-block;
        padding: 5px 14px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    .result-score {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1;
    }
    .result-score-label {
        font-size: 0.8rem;
        color: #9ca3af;
        text-align: center;
        margin-top: 2px;
    }

    /* Data grid */
    .data-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 16px;
    }
    .data-item {
        padding: 14px 16px;
        border-radius: 10px;
        background: #f9fafb;
        border: 1px solid #f3f4f6;
    }
    .data-item-label {
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #9ca3af;
        margin-bottom: 5px;
    }
    .data-item-value {
        font-size: 0.95rem;
        font-weight: 500;
        color: #111827;
    }

    /* Tool status badge */
    .tool-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 12px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 500;
        margin: 0 6px 6px 0;
    }
    .tool-badge.active {
        background: #ecfdf5;
        color: #065f46;
        border: 1px solid #a7f3d0;
    }
    .tool-badge.inactive {
        background: #fef3c7;
        color: #92400e;
        border: 1px solid #fde68a;
    }
    .tool-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }
    .tool-dot.green { background: #10b981; }
    .tool-dot.amber { background: #f59e0b; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #fafafa;
        border-right: 1px solid #e5e7eb;
    }

    /* Footer */
    .footer-meta {
        font-size: 0.78rem;
        color: #d1d5db;
        text-align: center;
        margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# ── Load backend ─────────────────────────────────────────────────────────────
from pipeline.orchestrator import PipelineOrchestrator
from pipeline.ioc_parser import IOC, IOCParser


@st.cache_resource
def get_orchestrator():
    config_path = "config.yaml"
    config = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    return PipelineOrchestrator(config)


orchestrator = get_orchestrator()

# ── Severity styling ─────────────────────────────────────────────────────────
SEVERITY_CONFIG = {
    "critical": {"color": "#dc2626", "bg": "#fef2f2", "border": "#fecaca", "label": "Critical"},
    "high":     {"color": "#ea580c", "bg": "#fff7ed", "border": "#fed7aa", "label": "High"},
    "medium":   {"color": "#d97706", "bg": "#fffbeb", "border": "#fde68a", "label": "Medium"},
    "low":      {"color": "#059669", "bg": "#ecfdf5", "border": "#a7f3d0", "label": "Low"},
    "none":     {"color": "#6b7280", "bg": "#f9fafb", "border": "#e5e7eb", "label": "None"},
    "error":    {"color": "#dc2626", "bg": "#fef2f2", "border": "#fecaca", "label": "Error"},
}


def build_result_html(result: dict) -> str:
    """Build a single clean, professional result card."""
    ioc = result["ioc"]
    score = result.get("score", {})
    results = result.get("results", {})
    was_cached = result.get("was_cached", False)
    elapsed = result.get("elapsed", 0)

    score_val = score.get("score", 0)
    severity = score.get("severity", "none")
    cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["none"])

    # ── Build data rows ──────────────────────────────────────────────────
    data_rows = ""

    for tool_name in ["ipinfo", "abuseipdb", "virustotal"]:
        tr = results.get(tool_name, {})
        if not tr.get("success") or not tr.get("data"):
            continue
        data = tr["data"]

        if tool_name == "ipinfo":
            location_parts = [p for p in [data.get("city"), data.get("region"), data.get("country")] if p]
            location = ", ".join(location_parts) if location_parts else "Unknown"

            items = [
                ("📍 Location", location),
                ("🌐 ISP", data.get("isp", "Unknown")),
                ("🔢 ASN", data.get("asn", "Unknown")),
                ("🏳️ Country", f"{data.get('country', '?')} {'⚠️ High-risk' if data.get('high_risk_country') else ''}"),
                ("🕐 Timezone", data.get("timezone", "Unknown")),
                ("🖥️ Hostname", data.get("hostname") or "None"),
            ]
        elif tool_name == "abuseipdb":
            items = [
                ("⚠️ Abuse Score", f"{data.get('abuse_confidence_score', 0)} / 100"),
                ("📋 Total Reports", str(data.get("total_reports", 0))),
                ("👥 Distinct Users", str(data.get("num_distinct_users", 0))),
                ("🏳️ Country", data.get("country_name", "Unknown")),
                ("🏢 ISP", data.get("isp", "Unknown")),
                ("📅 Last Reported", str(data.get("last_reported_at") or "Unknown")),
            ]
        elif tool_name == "virustotal":
            items = [
                ("🦠 Malicious", f"{data.get('malicious_detections', 0)} / {data.get('total_engines', 0)} engines"),
                ("⚠️ Suspicious", str(data.get("suspicious_detections", 0))),
                ("✅ Harmless", str(data.get("harmless", 0))),
                ("🏳️ Country", data.get("country", "Unknown")),
                ("🏷️ Reputation", str(data.get("reputation", 0))),
            ]
        else:
            continue

        for label, value in items:
            data_rows += f"""
            <div class="data-item">
                <div class="data-item-label">{label}</div>
                <div class="data-item-value">{value}</div>
            </div>"""

    meta = ""
    if was_cached:
        meta += " ⚡ From cache"
    if elapsed:
        meta += f" · ⏱ {elapsed}s"

    source_info = f"{ioc.source}"
    if ioc.context:
        source_info += f" — {ioc.context}"

    html = f"""
    <div class="result-card">
        <div class="result-header">
            <div>
                <div class="result-ioc-type">{ioc.type}</div>
                <div class="result-ioc-value">{ioc.value}</div>
                <div style="margin-top:6px;font-size:0.8rem;color:#9ca3af;">
                    Source: {source_info}{meta}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="margin-bottom:4px;">
                    <span class="result-badge" style="color:{cfg['color']};background:{cfg['bg']};border:1px solid {cfg['border']};">
                        {cfg['label']}
                    </span>
                </div>
                <div class="result-score" style="color:{cfg['color']};">
                    {score_val:.1f}
                </div>
                <div class="result-score-label">out of 10</div>
            </div>
        </div>
        <div class="data-grid">
            {data_rows}
        </div>
    </div>
    """
    return html


# ── Example IOCs for quick lookup ────────────────────────────────────────────
EXAMPLES = [
    ("8.8.8.8", "Google DNS"),
    ("185.130.5.173", "Known C2 server"),
    ("45.33.32.156", "Scanner activity"),
    ("1.1.1.1", "Cloudflare DNS"),
]

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ IOC Enrichment")
    st.caption("Threat intelligence lookup for security analysts.")

    st.markdown("---")

    st.markdown("#### Tools Available")
    tools = orchestrator.manager.available_tools

    for name, desc in tools.items():
        needs_key = name in ("virustotal", "abuseipdb")
        has_key = bool(os.getenv(f"{name.upper()}_API_KEY", "")) if needs_key else True

        if has_key:
            badge = f'<span class="tool-badge active"><span class="tool-dot green"></span> {name}</span>'
        else:
            badge = f'<span class="tool-badge inactive"><span class="tool-dot amber"></span> {name} (needs key)</span>'

        st.markdown(badge, unsafe_allow_html=True)
        st.caption(desc[:80])

    st.markdown("---")
    st.markdown("#### How it works")
    st.caption(
        "1. Type an IP, domain, or hash\n"
        "2. The pipeline checks threat databases\n"
        "3. You get a risk score and details\n\n"
        "No API keys needed for basic IP lookups."
    )

    st.markdown("---")
    st.caption("Pipeline v1.0 · MIT License")

# ── Hero ─────────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="hero-title">Look up any IP, domain, or file hash</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="hero-subtitle">'
    'Paste an indicator and get instant threat intelligence — geolocation, abuse reports, '
    'malware detections, and a risk score.'
    '</div>',
    unsafe_allow_html=True,
)

# ── Search row ───────────────────────────────────────────────────────────────
col_input, col_button = st.columns([5, 1])

with col_input:
    ioc_value = st.text_input(
        "indicator_value",
        placeholder="Paste an IP, domain, or hash here — e.g. 8.8.8.8 or evil.com",
        label_visibility="collapsed",
        key="main_input",
    )

with col_button:
    enrich_clicked = st.button("Look Up", type="primary", use_container_width=True)

# ── Example chips ────────────────────────────────────────────────────────────
st.markdown(
    '<div style="margin-top:4px;margin-bottom:8px;">'
    '<span style="font-size:0.8rem;color:#9ca3af;margin-right:8px;">Try an example:</span>'
    '</div>',
    unsafe_allow_html=True,
)

example_cols = st.columns(len(EXAMPLES))
clicked_example = None

for i, (example_val, example_desc) in enumerate(EXAMPLES):
    with example_cols[i]:
        if st.button(
            f"{example_val}\n{example_desc}",
            key=f"ex_{i}",
            use_container_width=True,
            help=f"Look up {example_val} ({example_desc})",
        ):
            clicked_example = example_val

# If an example chip was clicked, use its value
if clicked_example:
    ioc_value = clicked_example
    enrich_clicked = True

# ── Divider ──────────────────────────────────────────────────────────────────
st.markdown('<hr style="margin:24px 0;border-color:#f3f4f6;">', unsafe_allow_html=True)

# ── Enrichment logic ─────────────────────────────────────────────────────────
if enrich_clicked and ioc_value:
    with st.spinner(f"Looking up {ioc_value}..."):
        try:
            # Auto-detect type
            detected = IOCParser.detect_type(ioc_value.strip())
            ioc = IOC(type=detected, value=ioc_value.strip())

            result = orchestrator.process_ioc(ioc, use_llm=False)

            # Render result
            html = build_result_html(result)
            st.markdown(html, unsafe_allow_html=True)

            # Show which tools returned what
            with st.expander("📊 View raw enrichment data"):
                for tool_name, tr in result.get("results", {}).items():
                    success = tr.get("success")
                    icon = "✅" if success else "❌"
                    st.caption(f"{icon} **{tool_name}** — {tr.get('latency', 0):.2f}s")
                    if success and tr.get("data"):
                        st.json(tr["data"])
                    elif tr.get("error"):
                        st.caption(f"_{tr['error']}_")

        except Exception as e:
            st.error(f"Could not look up this indicator. {e}")

elif enrich_clicked and not ioc_value:
    st.warning("⚠️ Type or paste something above first.")

# ── Empty state guidance ─────────────────────────────────────────────────────
if not enrich_clicked:
    st.markdown("### What can you look up?")

    guide_col1, guide_col2, guide_col3, guide_col4 = st.columns(4)

    with guide_col1:
        st.markdown(
            """
            **IP Address**
            
            Any IPv4 address.
            
            Gets you: location, ISP,
            ASN, timezone, and whether
            it's from a risky country.
            
            *Example: 8.8.8.8*
            """
        )

    with guide_col2:
        st.markdown(
            """
            **Domain Name**
            
            Websites and servers.
            
            (Needs API key for full
            results — without one,
            only basic info is shown.)
            
            *Example: evil.com*
            """
        )

    with guide_col3:
        st.markdown(
            """
            **File Hash**
            
            MD5, SHA-1, or SHA-256.
            
            (Needs API key to check
            against 70+ antivirus
            engines via VirusTotal.)
            
            *Example: d41d8cd9...*
            """
        )

    with guide_col4:
        st.markdown(
            """
            **URL**
            
            Full web addresses.
            
            (Needs API key for
            VirusTotal URL scan.)
            
            *Example: http://...*
            """
        )

    st.markdown("---")

# ── Batch upload ─────────────────────────────────────────────────────────────
with st.expander("📂 Upload a file with multiple indicators (batch processing)"):
    st.markdown(
        "Upload a CSV or JSON file. Each indicator will be looked up automatically. "
        "Your file should have columns: **type**, **value**, **source**, **context**."
    )

    sample_csv = """type,value,source,context
ip,8.8.8.8,alerts,Google DNS
ip,185.130.5.173,threat_intel,C2 server
domain,evilphishing.xyz,phishing,Reported phishing"""

    st.code(sample_csv, language="csv")

    uploaded_file = st.file_uploader(
        "Choose a CSV or JSON file",
        type=["csv", "json"],
        label_visibility="collapsed",
    )

    if uploaded_file:
        temp_path = f"/tmp/uploaded_{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.spinner(f"Processing {uploaded_file.name}..."):
            try:
                results = orchestrator.process_file(temp_path)
                st.success(f"Done — processed {len(results)} indicators")

                for result in results:
                    html = build_result_html(result)
                    st.markdown(html, unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Error reading file: {e}")

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="footer-meta">IOC Enrichment Pipeline v1.0 — MIT License</div>',
    unsafe_allow_html=True,
)