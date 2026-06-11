"""
IOC Enrichment Pipeline — Web UI

Usage:
    streamlit run app.py
    # Opens at http://localhost:8501

This is a simple graphical interface for the enrichment pipeline.
No terminal commands needed — just paste an IOC and click.
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
    page_title="IOC Enrichment Pipeline",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

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

# ── Severity colors ──────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "none": "#6c757d",
    "error": "#dc3545",
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#6c757d")


def format_enrichment_result(result: dict):
    """Render a single enrichment result as a card."""
    ioc = result["ioc"]
    score = result.get("score", {})
    results = result.get("results", {})
    was_cached = result.get("was_cached", False)

    score_val = score.get("score", 0)
    severity = score.get("severity", "none")
    color = severity_color(severity)

    # ── Header card ──────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div style="
            border: 1px solid {color}40;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            background: {'#0d1117' if st.get_option('theme.base') != 'light' else '#ffffff'};
        ">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="
                        background: {color}20;
                        color: {color};
                        padding: 4px 10px;
                        border-radius: 6px;
                        font-size: 12px;
                        font-weight: 600;
                        text-transform: uppercase;
                    ">{ioc.type}</span>
                    <span style="
                        font-size: 18px;
                        font-weight: 600;
                        margin-left: 12px;
                        font-family: 'Courier New', monospace;
                    ">{ioc.value}</span>
                </div>
                <div style="text-align: right;">
                    <div style="
                        font-size: 28px;
                        font-weight: 700;
                        color: {color};
                    ">{score_val:.1f}<span style="font-size: 14px; color: #888;">/10</span></div>
                    <div style="
                        color: {color};
                        font-weight: 600;
                        font-size: 12px;
                        text-transform: uppercase;
                    ">{severity}</div>
                </div>
            </div>
            <div style="margin-top: 8px; color: #888; font-size: 13px;">
                Source: {ioc.source}  |  Context: {ioc.context or 'N/A'}
                {'  |  ⚡ Cached' if was_cached else ''}
                {'  |  ⏱ ' + str(result.get('elapsed', 0)) + 's' if result.get('elapsed') else ''}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Scoring breakdown ────────────────────────────────────────────────────
    factors = score.get("factors", {})
    if factors:
        st.markdown("##### Scoring Breakdown")
        cols = st.columns(min(len(factors), 5))
        for i, (name, factor) in enumerate(factors.items()):
            with cols[i % len(cols)]:
                contribution = factor.get("contribution", 0)
                detail = factor.get("detail", "")
                st.markdown(
                    f"""
                    <div style="
                        background: {'#161b22' if st.get_option('theme.base') != 'light' else '#f6f8fa'};
                        border-radius: 8px;
                        padding: 12px;
                        margin-bottom: 8px;
                    ">
                        <div style="font-size: 11px; color: #888; text-transform: uppercase; font-weight: 600;">
                            {name.replace('_', ' ')}
                        </div>
                        <div style="font-size: 14px; font-weight: 600; margin-top: 4px;">
                            +{contribution:.1f}
                        </div>
                        <div style="font-size: 11px; color: #888; margin-top: 4px;">
                            {detail[:80]}{'...' if len(detail) > 80 else ''}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # ── Enrichment details ───────────────────────────────────────────────────
    st.markdown("##### Enrichment Results")
    for tool_name, tool_result in results.items():
        success = tool_result.get("success", False)
        latency = tool_result.get("latency", 0)
        error = tool_result.get("error")
        data = tool_result.get("data", {})

        status_icon = "✅" if success else "❌"
        with st.expander(f"{status_icon} {tool_name.upper()} ({latency:.2f}s)"):
            if success and data:
                for key, value in data.items():
                    if isinstance(value, list):
                        st.text(f"{key}: {', '.join(str(v) for v in value[:5])}")
                    elif isinstance(value, dict):
                        st.json(value)
                    else:
                        st.text(f"{key}: {value}")
            elif error:
                st.error(error)
            else:
                st.info("No data returned")

    st.markdown("---")


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🔍 IOC Enrichment")
    st.markdown("**Automated threat intel enrichment for SOC analysts**")
    st.markdown("---")

    # Show tool status
    st.markdown("##### Available Tools")
    tools = orchestrator.manager.available_tools
    for name, desc in tools.items():
        needs_key = name in ("virustotal", "abuseipdb")
        if needs_key:
            import os as _os
            has_key = bool(_os.getenv(f"{name.upper()}_API_KEY", ""))
            status = "✅" if has_key else "⚠️ No key"
        else:
            status = "✅"
        st.markdown(f"{status} **{name}** — {desc[:50]}...")

    st.markdown("---")
    st.markdown(
        """
        **How to use:**
        1. Enter an IOC value (IP, domain, hash, URL)
        2. Select the type (or auto-detect)
        3. Click **Enrich**

        Or upload a CSV/JSON file for batch processing.
        """
    )

    st.markdown("---")
    st.caption(f"Pipeline v1.0.0")

# ── Main panel ───────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🎯 Single IOC", "📂 Batch File", "📊 Cache & Stats"])

# ── Tab 1: Single IOC ────────────────────────────────────────────────────────
with tab1:
    col1, col2, col3 = st.columns([3, 1, 1])

    with col1:
        ioc_value = st.text_input(
            "IOC Value",
            placeholder="e.g., 8.8.8.8, example.com, or a file hash...",
            label_visibility="collapsed",
        )

    with col2:
        ioc_type = st.selectbox(
            "Type",
            ["auto", "ip", "domain", "hash", "url", "email"],
            index=0,
            label_visibility="collapsed",
        )

    with col3:
        enrich_clicked = st.button("🔍 Enrich", type="primary", use_container_width=True)

    # LLM summary option
    llm_enabled = bool(os.getenv("OPENROUTER_API_KEY"))
    use_llm = st.checkbox("Generate AI threat summary", disabled=not llm_enabled,
                          help="Requires OPENROUTER_API_KEY in .env" if not llm_enabled else "")

    if enrich_clicked and ioc_value:
        with st.spinner(f"Enriching {ioc_value}..."):
            try:
                if ioc_type == "auto":
                    detected = IOCParser.detect_type(ioc_value)
                    ioc = IOC(type=detected, value=ioc_value)
                else:
                    ioc = IOC(type=ioc_type, value=ioc_value)

                result = orchestrator.process_ioc(ioc, use_llm=use_llm)

                format_enrichment_result(result)

                # LLM summary if available
                if result.get("llm_summary"):
                    st.markdown("##### 🤖 AI Threat Summary")
                    st.info(result["llm_summary"])

            except Exception as e:
                st.error(f"Error: {e}")

    elif enrich_clicked and not ioc_value:
        st.warning("Enter an IOC value first")

# ── Tab 2: Batch File ────────────────────────────────────────────────────────
with tab2:
    st.markdown("Upload a CSV or JSON file with multiple IOCs.")

    sample_csv = """type,value,source,context
ip,8.8.8.8,alerts,Google DNS
ip,185.130.5.173,threat_intel,C2 server
domain,evilphishing.xyz,phishing,Reported phishing
hash,e3b0c44298fc1c149afbf4c8996fb924,alerts,Suspicious hash"""

    with st.expander("📄 Show sample CSV format"):
        st.code(sample_csv, language="csv")

    uploaded_file = st.file_uploader(
        "Upload CSV or JSON",
        type=["csv", "json"],
        label_visibility="collapsed",
    )

    if uploaded_file:
        # Save uploaded file temporarily
        temp_path = f"/tmp/uploaded_{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.spinner(f"Processing {uploaded_file.name}..."):
            try:
                results = orchestrator.process_file(temp_path)
                st.success(f"✅ Processed {len(results)} IOC(s)")

                for result in results:
                    format_enrichment_result(result)

            except Exception as e:
                st.error(f"Error: {e}")

# ── Tab 3: Cache & Stats ────────────────────────────────────────────────────
with tab3:
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("##### Enrichment Cache")
        cache_stats = orchestrator.cache.stats()

        cache_data = {
            "Total entries": cache_stats.get("total_entries", 0),
            "Expired": cache_stats.get("expired_entries", 0),
            "Hit rate": f"{cache_stats.get('hit_rate', 0):.1%}",
            "Cache hits": cache_stats.get("hits", 0),
            "Cache misses": cache_stats.get("misses", 0),
        }

        for label, value in cache_data.items():
            st.metric(label, value)

        if st.button("🗑️ Clear Cache", type="secondary"):
            orchestrator.cache.clear()
            st.rerun()

    with col2:
        st.markdown("##### Enrichment Stats")
        enrich_stats = orchestrator.get_stats().get("enrichment_stats", {})
        tool_stats = enrich_stats.get("tool_stats", {})

        for tool_name, tstats in tool_stats.items():
            st.markdown(f"**{tool_name}**")
            st.metric("Calls", tstats.get("calls", 0))
            st.metric("Errors", tstats.get("errors", 0))

    st.markdown("---")
    st.markdown("##### Quick Run")
    st.markdown("Click below to enrich a test IOC:")
    if st.button("▶️ Test: Enrich 8.8.8.8"):
        with st.spinner("Enriching..."):
            ioc = IOC(type="ip", value="8.8.8.8")
            result = orchestrator.process_ioc(ioc)
            format_enrichment_result(result)

    if st.button("▶️ Test: Batch 10 IOCs from sample file"):
        with st.spinner("Processing..."):
            results = orchestrator.process_file("tests/sample_iocs.csv")
            st.success(f"✅ Processed {len(results)} IOC(s)")
            for result in results:
                format_enrichment_result(result)