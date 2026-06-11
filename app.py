"""
IOC Enrichment Pipeline — Professional Web UI
Double-click launch.bat or run: streamlit run app.py → http://localhost:8501
"""
import streamlit as st
import sys
import os
import time
import json

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
    initial_sidebar_state="auto",
)

# ── Theme ────────────────────────────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state.theme = "system"

is_dark = st.get_option("theme.base") == "dark"
if st.session_state.theme == "dark":
    is_dark = True
elif st.session_state.theme == "light":
    is_dark = False

# ── CSS variables ────────────────────────────────────────────────────────────
if is_dark:
    BG         = "#0d1117"
    BG_CARD    = "#161b22"
    BG_CELL    = "#0d1117"
    BORDER     = "#30363d"
    BORDER_L   = "#21262d"
    TEXT       = "#e6edf3"
    TEXT_MUTED = "#8b949e"
    TEXT_DIM   = "#484f58"
    INPUT_BG   = "#0d1117"
    PLACEHOLDER = "#6b7280"
    HOVER_BG   = "#1c2128"
    SOLID_BG   = "#1c2128"
else:
    BG         = "#ffffff"
    BG_CARD    = "#ffffff"
    BG_CELL    = "#f9fafb"
    BORDER     = "#e5e7eb"
    BORDER_L   = "#f3f4f6"
    TEXT       = "#111827"
    TEXT_MUTED = "#6b7280"
    TEXT_DIM   = "#d1d5db"
    INPUT_BG   = "#fafafa"
    PLACEHOLDER = "#9ca3af"
    HOVER_BG   = "#f3f4f6"
    SOLID_BG   = "#f3f4f6"

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    * {{ font-family: 'Inter', sans-serif; }}
    html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}
    #MainMenu, footer, header, .stAppToolbar {{ visibility: hidden; }}
    .stApp {{ margin-top: -60px; background: {BG}; }}
    .stAppHeader {{ background: transparent !important; }}
    .st-emotion-cache-1avcm0n {{ background: {BG}; }}
    div[data-testid="stToolbar"] {{ display: none; }}

    /* ── Scrollbar ── */
    ::-webkit-scrollbar {{ width: 6px; }}
    ::-webkit-scrollbar-track {{ background: {BG}; }}
    ::-webkit-scrollbar-thumb {{ background: {BORDER}; border-radius: 3px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: {TEXT_MUTED}; }}

    /* ── Brand ── */
    .brand {{
        display: flex; align-items: center; justify-content: center; gap: 14px;
        margin: 48px 0 6px 0;
    }}
    .brand-icon {{
        width: 44px; height: 44px; background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 12px; display: flex; align-items: center; justify-content: center;
        font-size: 1.4rem; box-shadow: 0 4px 16px rgba(99,102,241,0.3);
        flex-shrink: 0;
    }}
    .brand-title {{
        font-size: 1.85rem; font-weight: 800; color: {TEXT};
        letter-spacing: -0.03em; line-height: 1.2;
    }}
    .hero-subtitle {{
        text-align: center; font-size: 1rem; color: {TEXT_MUTED}; margin-bottom: 28px;
        line-height: 1.6; max-width: 500px; margin-left: auto; margin-right: auto;
    }}

    /* ── Search container ── */
    .search-container {{
        max-width: 560px; margin: 0 auto;
    }}
    .search-container .stForm {{
        background: transparent !important; padding: 0 !important;
        border: none !important; box-shadow: none !important;
    }}
    .search-container .stForm [data-testid="stForm"] {{
        background: transparent !important; padding: 0 !important;
        border: none !important; box-shadow: none !important;
    }}

    /* Style the text input inside the form */
    .search-container div[data-testid="stTextInput"] {{
        margin-bottom: 0 !important;
    }}
    .search-container div[data-testid="stTextInput"] input {{
        width: 100%; padding: 15px 20px 15px 48px; font-size: 1rem;
        border: 2px solid {BORDER}; border-radius: 12px; outline: none;
        font-family: 'JetBrains Mono', monospace; background: {INPUT_BG}; color: {TEXT};
        transition: all 0.2s ease; box-sizing: border-box; height: 52px;
    }}
    .search-container div[data-testid="stTextInput"] input:focus {{
        border-color: #6366f1; background: {BG}; box-shadow: 0 0 0 4px rgba(99,102,241,0.12);
    }}
    .search-container div[data-testid="stTextInput"] input::placeholder {{
        color: {PLACEHOLDER} !important; font-family: 'Inter', sans-serif; opacity: 1;
    }}
    .search-container div[data-testid="stTextInput"] input::-webkit-input-placeholder {{
        color: {PLACEHOLDER} !important; font-family: 'Inter', sans-serif;
    }}
    .search-container div[data-testid="stTextInput"] input::-moz-placeholder {{
        color: {PLACEHOLDER} !important; font-family: 'Inter', sans-serif;
    }}
    .search-container div[data-testid="stTextInput"] input:-ms-input-placeholder {{
        color: {PLACEHOLDER} !important; font-family: 'Inter', sans-serif;
    }}
    .search-icon {{
        position: relative; margin-bottom: -42px; left: 18px; top: 6px;
        z-index: 10; font-size: 1rem; color: {TEXT_MUTED};
    }}

    /* ── Submit button ── */
    .search-container .stForm button {{
        background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
        border: none !important; border-radius: 10px !important;
        font-weight: 600 !important; font-size: 0.95rem !important;
        height: 48px; color: white !important; box-shadow: 0 2px 8px rgba(99,102,241,0.25) !important;
        transition: all 0.2s ease !important;
    }}
    .search-container .stForm button:hover {{
        box-shadow: 0 4px 16px rgba(99,102,241,0.4) !important;
        transform: translateY(-1px);
    }}
    .search-container .stForm button:active {{
        transform: translateY(0);
    }}

    /* ── Example chips ── */
    .chips-container {{
        max-width: 560px; margin: 10px auto 0 auto;
        display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    }}
    .chips-label {{
        font-size: 0.78rem; color: {TEXT_MUTED}; font-weight: 500;
        margin-right: 4px; white-space: nowrap;
    }}
    .chip {{
        display: inline-block; padding: 5px 14px; border-radius: 100px;
        font-size: 0.78rem; font-weight: 500; font-family: 'JetBrains Mono', monospace;
        border: 1px solid {BORDER}; color: {TEXT_MUTED}; background: transparent;
        cursor: pointer; transition: all 0.15s ease; text-decoration: none;
        line-height: 1.5;
    }}
    .chip:hover {{
        background: {HOVER_BG}; border-color: #6366f1; color: #a5b4fc;
    }}

    /* ── Hide raw stButton inside chips container ── */
    .chips-container div[data-testid="stButton"] button {{
        padding: 5px 14px !important; border-radius: 100px !important;
        font-size: 0.78rem !important; font-weight: 500 !important;
        font-family: 'JetBrains Mono', monospace !important;
        border: 1px solid {BORDER} !important; color: {TEXT_MUTED} !important;
        background: transparent !important; height: auto !important;
        transition: all 0.15s ease !important; line-height: 1.5 !important;
        box-shadow: none !important;
    }}
    .chips-container div[data-testid="stButton"] button:hover {{
        background: {HOVER_BG} !important; border-color: #6366f1 !important;
        color: #a5b4fc !important; transform: none !important;
    }}

    /* ── Result card ── */
    .result-card {{
        max-width: 640px; margin: 24px auto; border: 1px solid {BORDER};
        border-radius: 14px; overflow: hidden; background: {BG_CARD};
        box-shadow: 0 1px 4px rgba(0,0,0,0.04);
        animation: fadeIn 0.25s ease;
    }}
    @keyframes fadeIn {{
        from {{ opacity: 0; transform: translateY(8px); }}
        to   {{ opacity: 1; transform: translateY(0); }}
    }}
    .result-top {{
        display: flex; justify-content: space-between; align-items: flex-start;
        padding: 20px 24px; border-bottom: 1px solid {BORDER_L};
    }}
    .result-type-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 6px;
        font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.06em;
    }}
    .result-value {{
        font-size: 1.15rem; font-weight: 700; color: {TEXT};
        font-family: 'JetBrains Mono', monospace; margin-top: 6px;
        word-break: break-all;
    }}
    .result-meta {{
        font-size: 0.75rem; color: {TEXT_MUTED}; margin-top: 4px;
    }}
    .result-meta .tag {{
        display: inline-block; padding: 1px 7px; border-radius: 4px;
        font-size: 0.65rem; font-weight: 600;
        margin-left: 4px; vertical-align: middle;
    }}
    .tag-cached {{
        background: rgba(16,185,129,0.1); color: #10b981; border: 1px solid rgba(16,185,129,0.2);
    }}
    .score-ring {{
        width: 68px; height: 68px; border-radius: 50%; display: flex;
        flex-direction: column; align-items: center; justify-content: center;
        font-weight: 800; flex-shrink: 0;
    }}
    .score-number {{ font-size: 1.35rem; line-height: 1; }}
    .score-label {{ font-size: 0.55rem; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.7; margin-top: 1px; }}
    .score-severity {{
        display: inline-block; padding: 2px 10px; border-radius: 4px;
        font-size: 0.6rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.05em; margin-top: 3px;
    }}

    /* ── Data grid ── */
    .data-section {{ padding: 4px 24px 18px 24px; }}
    .data-section-title {{
        font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.07em; color: {TEXT_MUTED}; margin: 14px 0 8px 0;
        padding-bottom: 5px; border-bottom: 1px solid {BORDER_L};
    }}
    .data-grid {{
        display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
        gap: 8px;
    }}
    .data-cell {{
        padding: 10px 12px; border-radius: 8px; background: {BG_CELL};
        border: 1px solid {BORDER_L};
    }}
    .data-cell-label {{
        font-size: 0.62rem; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.05em; color: {TEXT_MUTED}; margin-bottom: 2px;
    }}
    .data-cell-value {{
        font-size: 0.85rem; font-weight: 500; color: {TEXT}; word-break: break-all;
    }}

    /* ── Tool row ── */
    .tool-row {{
        display: flex; align-items: center; gap: 10px; padding: 8px 24px;
        font-size: 0.72rem; color: {TEXT_MUTED}; border-top: 1px solid {BORDER_L};
        flex-wrap: wrap;
    }}
    .tool-dot {{ width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; display: inline-block; }}
    .tool-dot.ok {{ background: #10b981; box-shadow: 0 0 4px rgba(16,185,129,0.3); }}
    .tool-dot.warn {{ background: #f59e0b; }}
    .tool-dot.err {{ background: #ef4444; }}
    .tool-name {{ font-weight: 500; }}

    /* ── Error state ── */
    .error-box {{
        max-width: 560px; margin: 20px auto; padding: 14px 18px;
        border-radius: 10px; background: rgba(239,68,68,0.08);
        border: 1px solid rgba(239,68,68,0.2); color: {TEXT};
        font-size: 0.9rem;
    }}
    .error-box .error-icon {{ margin-right: 8px; }}

    /* ── Empty state ── */
    .empty-grid {{
        display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
        max-width: 640px; margin: 28px auto 0 auto;
    }}
    .empty-card {{
        padding: 18px 14px; border-radius: 11px; border: 1px solid {BORDER_L};
        text-align: center; background: {BG_CELL};
        transition: all 0.15s ease;
    }}
    .empty-card:hover {{
        border-color: {BORDER}; background: {HOVER_BG};
    }}
    .empty-card-icon {{ font-size: 1.4rem; margin-bottom: 6px; }}
    .empty-card-title {{ font-size: 0.8rem; font-weight: 700; color: {TEXT}; margin-bottom: 3px; }}
    .empty-card-desc {{ font-size: 0.7rem; color: {TEXT_MUTED}; line-height: 1.4; }}

    /* ── LLM summary ── */
    .llm-box {{
        max-width: 640px; margin: 16px auto; padding: 14px 18px;
        border-radius: 10px; background: rgba(99,102,241,0.06);
        border: 1px solid rgba(99,102,241,0.15); color: {TEXT};
        font-size: 0.85rem; line-height: 1.6;
    }}
    .llm-box .llm-label {{
        font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.06em; color: #8b5cf6; margin-bottom: 4px;
    }}

    /* ── Batch section ── */
    .batch-section {{
        max-width: 640px; margin: 0 auto; padding-top: 8px;
    }}
    .batch-section .stFileUploader div[data-testid="stFileUploadDropzone"] {{
        border: 2px dashed {BORDER} !important; border-radius: 10px !important;
        background: {BG_CELL} !important; padding: 20px !important;
    }}
    .batch-section .stFileUploader div[data-testid="stFileUploadDropzone"]:hover {{
        border-color: #6366f1 !important;
    }}

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {{ background: {BG_CELL}; border-right: 1px solid {BORDER}; }}
    section[data-testid="stSidebar"] .stSidebarContent {{ padding-top: 1.5rem; }}

    /* ── Footer ── */
    .footer {{ text-align: center; font-size: 0.72rem; color: {TEXT_DIM}; margin-top: 40px; padding-bottom: 20px; }}
    .footer a {{ color: {TEXT_MUTED}; text-decoration: none; }}
    .footer a:hover {{ color: #6366f1; }}

    /* ── Divider ── */
    .section-divider {{
        margin: 24px 0; border: none; height: 1px;
        background: {BORDER_L};
    }}

    /* ── Selectbox in sidebar ── */
    section[data-testid="stSidebar"] div[data-testid="stSelectbox"] label {{
        display: none !important;
    }}
    section[data-testid="stSidebar"] div[data-testid="stSelectbox"] {{
        margin-bottom: 0 !important;
    }}
    section[data-testid="stSidebar"] div[data-testid="stSelectbox"] > div {{
        border-radius: 8px; border-color: {BORDER}; background: {BG};
        color: {TEXT}; font-size: 0.8rem;
    }}
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

# ── Severity config ──────────────────────────────────────────────────────────
SEVERITY = {
    "critical": {"color": "#dc2626", "bg": "#fef2f2", "ring": "#fecaca", "bg_dark": "#2d1215"},
    "high":     {"color": "#ea580c", "bg": "#fff7ed", "ring": "#fed7aa", "bg_dark": "#2d1a0e"},
    "medium":   {"color": "#d97706", "bg": "#fffbeb", "ring": "#fde68a", "bg_dark": "#2d2008"},
    "low":      {"color": "#059669", "bg": "#ecfdf5", "ring": "#a7f3d0", "bg_dark": "#0d1f17"},
    "none":     {"color": "#6b7280", "bg": "#f9fafb", "ring": "#e5e7eb", "bg_dark": "#1c1c1c"},
}

TOOL_NAMES = ["ipinfo", "abuseipdb", "virustotal"]


def tool_has_key(name: str) -> bool:
    if name == "ipinfo":
        return True
    return bool(os.getenv(f"{name.upper()}_API_KEY", ""))


def build_result_card(result: dict) -> str:
    """Build a fully styled HTML result card from enrichment output."""
    ioc = result["ioc"]
    score = result.get("score", {})
    results = result.get("results", {})

    score_val = score.get("score", 0)
    sev = score.get("severity", "none")
    cfg = SEVERITY.get(sev, SEVERITY["none"])
    elapsed = result.get("elapsed", 0)

    sev_bg = cfg["bg_dark"] if is_dark else cfg["bg"]
    sev_ring = cfg["ring"]

    # ── Build data cells ──
    cells = []
    for tool_name in TOOL_NAMES:
        tr = results.get(tool_name, {})
        if not tr.get("success") or not tr.get("data"):
            continue
        data = tr["data"]

        # Skip if only a "note" field (tool gracefully skipped this type)
        if list(data.keys()) == ["note"]:
            continue

        if tool_name == "ipinfo":
            loc = ", ".join(filter(None, [data.get("city"), data.get("region"), data.get("country")]))
            risk = data.get("high_risk_country")
            location_text = loc or "Unknown"
            if risk:
                location_text += " ⚠️ High-risk"
            cells += [
                ("📍 Location", location_text),
                ("🌐 ISP", data.get("isp", "—")),
                ("🔢 ASN", data.get("asn", "—")),
                ("🏳️ Country", data.get("country", "—")),
                ("🕐 Timezone", data.get("timezone", "—")),
                ("🖥️ Hostname", data.get("hostname") or "—"),
            ]
        elif tool_name == "abuseipdb":
            cells += [
                ("⚠️ Abuse Score", f"{data.get('abuse_confidence_score', 0)}/100"),
                ("📋 Reports", str(data.get("total_reports", 0))),
                ("👥 Distinct Users", str(data.get("num_distinct_users", 0))),
                ("🏳️ Country", data.get("country_name", "—")),
                ("🏢 ISP", data.get("isp", "—")),
                ("📅 Last Reported", str(data.get("last_reported_at") or "—")),
            ]
        elif tool_name == "virustotal":
            note = data.get("note", "")
            cells += [
                ("🦠 Malicious", f"{data.get('malicious_detections', 0)}/{data.get('total_engines', 0)}"),
                ("⚠️ Suspicious", str(data.get("suspicious_detections", 0))),
                ("✅ Clean", str(data.get("harmless", 0))),
            ]
            if data.get("country"):
                cells.append(("🏳️ Country", data["country"]))
            if note:
                cells.append(("ℹ️ Note", note))

    cells_html = ""
    for label, value in cells:
        cells_html += f"""
        <div class="data-cell">
            <div class="data-cell-label">{label}</div>
            <div class="data-cell-value">{value}</div>
        </div>"""

    # ── Tool status dots ──
    tool_row_parts = []
    for name in TOOL_NAMES:
        tr = results.get(name, {})
        if tr.get("success") and tr.get("data"):
            if list(tr["data"].keys()) != ["note"]:
                status = "ok"
            else:
                status = "warn"
        elif tr.get("error"):
            status = "err"
        else:
            status = "warn"
        tool_row_parts.append(f'<span class="tool-dot {status}"></span><span class="tool-name">{name}</span>')
    tool_row = " ".join(tool_row_parts)

    # ── Meta line ──
    source = ioc.source
    if ioc.context:
        source += f" — {ioc.context}"
    meta_parts = [source, f"⏱ {elapsed:.2f}s"]
    if result.get("was_cached"):
        meta_parts.append('<span class="tag tag-cached">⚡ cached</span>')
    meta = " · ".join(meta_parts)

    return f"""
    <div class="result-card">
        <div class="result-top">
            <div>
                <span class="result-type-badge" style="background:{sev_bg};color:{cfg['color']};border:1px solid {sev_ring};">{ioc.type.upper()}</span>
                <div class="result-value">{ioc.value}</div>
                <div class="result-meta">{meta}</div>
            </div>
            <div style="text-align:center;flex-shrink:0;margin-left:16px;">
                <div class="score-ring" style="background:{sev_bg};border:3px solid {sev_ring};">
                    <div class="score-number" style="color:{cfg['color']};">{score_val:.1f}</div>
                    <div class="score-label">out of 10</div>
                </div>
                <div class="score-severity" style="color:{cfg['color']};background:{sev_bg};">{sev}</div>
            </div>
        </div>
        <div class="data-section">
            <div class="data-grid">{cells_html}</div>
            <div class="tool-row">{tool_row}</div>
        </div>
    </div>"""


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;padding-bottom:4px;">'
        f'<span style="font-size:1.3rem;">🛡️</span>'
        f'<span style="font-weight:700;font-size:1.05rem;color:{TEXT};">IOC Enrichment</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.caption("Threat intelligence lookup for SOC analysts.")

    st.markdown(f'<hr style="margin:14px 0;border-color:{BORDER_L};">', unsafe_allow_html=True)

    # ── Data sources ─────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="font-size:0.78rem;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:0.05em;color:{TEXT_MUTED};margin-bottom:8px;">Data Sources</div>',
        unsafe_allow_html=True,
    )

    for name in TOOL_NAMES:
        has = tool_has_key(name)
        tool_obj = orchestrator.manager._tools.get(name)
        desc = tool_obj.description if tool_obj else ""
        color = "#10b981" if has else (TEXT_DIM if is_dark else "#d1d5db")
        status_text = "Ready" if has else "No API key"
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;padding:4px 0;">'
            f'<span class="tool-dot {"ok" if has else "err"}" style="flex-shrink:0;"></span>'
            f'<div style="flex:1;">'
            f'<div style="font-size:0.82rem;font-weight:600;color:{TEXT};">{name}</div>'
            f'<div style="font-size:0.7rem;color:{TEXT_MUTED};line-height:1.3;">{desc[:60]}</div>'
            f'</div>'
            f'<span style="font-size:0.65rem;color:{color};font-weight:600;white-space:nowrap;">{status_text}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown(f'<hr style="margin:14px 0;border-color:{BORDER_L};">', unsafe_allow_html=True)

    # ── Appearance ───────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="font-size:0.78rem;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:0.05em;color:{TEXT_MUTED};margin-bottom:6px;">Appearance</div>',
        unsafe_allow_html=True,
    )
    theme_options = ["💻 System", "☀️ Light", "🌙 Dark"]
    current_idx = {"system": 0, "light": 1, "dark": 2}.get(st.session_state.theme, 0)
    theme_choice = st.selectbox(
        "Theme", theme_options, index=current_idx,
        label_visibility="collapsed", key="theme_selector",
    )
    theme_map = {"💻 System": "system", "☀️ Light": "light", "🌙 Dark": "dark"}
    chosen = theme_map[theme_choice]
    if chosen != st.session_state.theme:
        st.session_state.theme = chosen
        st.rerun()

    # ── Cache stats ──────────────────────────────────────────────────────────
    st.markdown(f'<hr style="margin:14px 0;border-color:{BORDER_L};">', unsafe_allow_html=True)
    st.markdown(
        f'<div style="font-size:0.78rem;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:0.05em;color:{TEXT_MUTED};margin-bottom:6px;">Cache</div>',
        unsafe_allow_html=True,
    )
    try:
        cache_stats = orchestrator.cache.stats()
        st.markdown(
            f'<div style="font-size:0.8rem;color:{TEXT_MUTED};line-height:1.7;">'
            f'<span style="font-weight:600;color:{TEXT};">{cache_stats["total_entries"]}</span> entries · '
            f'<span style="font-weight:600;color:{TEXT};">{cache_stats["hit_rate"]:.0%}</span> hit rate'
            f'</div>',
            unsafe_allow_html=True,
        )
    except Exception:
        pass

    st.markdown(
        f'<div style="margin-top:24px;font-size:0.68rem;color:{TEXT_DIM};">'
        f'Pipeline v1.0 · MIT License'
        f'</div>',
        unsafe_allow_html=True,
    )

# ── Main content ─────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([1, 3, 1])
with col2:
    # ── Brand ──
    st.markdown(f"""
    <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div class="brand-title">IOC Enrichment</div>
    </div>
    <div class="hero-subtitle">
        Look up any IP, domain, file hash, or URL against multiple threat intelligence sources.
        Get geolocation, abuse reports, malware detections, and a risk score — instantly.
    </div>
    """, unsafe_allow_html=True)

    # ── Initialize session state ──
    if "search_triggered" not in st.session_state:
        st.session_state.search_triggered = False
    if "search_value" not in st.session_state:
        st.session_state.search_value = ""
    if "show_batch" not in st.session_state:
        st.session_state.show_batch = False
    if "last_result" not in st.session_state:
        st.session_state.last_result = None
    if "last_error" not in st.session_state:
        st.session_state.last_error = None

    # ── Search form (Enter-to-submit) ──
    st.markdown('<div class="search-container">', unsafe_allow_html=True)

    st.markdown('<div class="search-icon">🔍</div>', unsafe_allow_html=True)

    with st.form("search_form", clear_on_submit=False):
        cols = st.columns([5, 1])
        with cols[0]:
            search_val = st.text_input(
                "ioc_search",
                placeholder="Paste an IP, domain, hash, or URL — e.g. 8.8.8.8",
                label_visibility="collapsed",
                key="search_input",
                value=st.session_state.get("search_value", ""),
            )
        with cols[1]:
            submitted = st.form_submit_button("Look Up", type="primary", use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Example chips ──
    example_map = {
        "8.8.8.8":        "Google DNS",
        "5.188.62.38":    "Russian IP",
        "iuqerfsodp9...": "Emotet C2 hash",
        "d41d8cd98f...":  "MD5 empty hash",
    }

    st.markdown('<div class="chips-container">', unsafe_allow_html=True)
    st.markdown(f'<span class="chips-label">Try:</span>', unsafe_allow_html=True)
    for val, label in example_map.items():
        if st.button(val, key=f"chip_{val}", help=label, use_container_width=False):
            st.session_state.search_value = val
            st.session_state.search_triggered = True
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Batch toggle ──
    bc1, bc2 = st.columns([1, 1])
    with bc1:
        pass
    with bc2:
        batch_label = "📂 Batch Upload" if not st.session_state.show_batch else "✕ Close Batch"
        if st.button(batch_label, use_container_width=True, key="batch_toggle"):
            st.session_state.show_batch = not st.session_state.show_batch
            st.rerun()

    st.markdown(f'<hr class="section-divider">', unsafe_allow_html=True)

    # ── Process search ──
    process_value = None
    if submitted and search_val.strip():
        process_value = search_val.strip()
    elif st.session_state.search_triggered and st.session_state.search_value:
        process_value = st.session_state.search_value.strip()
        st.session_state.search_triggered = False

    if process_value:
        with st.spinner("Looking up…"):
            try:
                detected = IOCParser.detect_type(process_value)
                ioc = IOC(type=detected, value=process_value)
                result = orchestrator.process_ioc(ioc)
                st.session_state.last_result = result
                st.session_state.last_error = None
                st.rerun()
            except Exception as e:
                st.session_state.last_error = str(e)
                st.session_state.last_result = None
                st.rerun()

    # ── Show result ──
    if st.session_state.last_result:
        st.markdown(build_result_card(st.session_state.last_result), unsafe_allow_html=True)

        # Show LLM summary if available
        llm_summary = st.session_state.last_result.get("llm_summary")
        if llm_summary:
            st.markdown(f"""
            <div class="llm-box">
                <div class="llm-label">🤖 AI Threat Summary</div>
                {llm_summary}
            </div>
            """, unsafe_allow_html=True)

    # ── Show error ──
    if st.session_state.last_error:
        st.markdown(f"""
        <div class="error-box">
            <span class="error-icon">⚠️</span>
            Could not process: {st.session_state.last_error}
        </div>
        """, unsafe_allow_html=True)

    # ── Empty state ──
    if not st.session_state.last_result and not st.session_state.last_error:
        st.markdown(f"""
        <div class="empty-grid">
            <div class="empty-card">
                <div class="empty-card-icon">🌐</div>
                <div class="empty-card-title">IP Address</div>
                <div class="empty-card-desc">Location, ISP, ASN, and whether it's from a risky country.</div>
            </div>
            <div class="empty-card">
                <div class="empty-card-icon">🔗</div>
                <div class="empty-card-title">Domain</div>
                <div class="empty-card-desc">Registrar, DNS records, malware detections from 70+ engines.</div>
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

    # ── Batch upload section ──
    if st.session_state.show_batch:
        st.markdown(f'<hr class="section-divider">', unsafe_allow_html=True)
        st.markdown("""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span style="font-size:1.1rem;">📂</span>
            <span style="font-weight:700;font-size:1rem;">Batch Processing</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(
            f'<div style="font-size:0.82rem;color:{TEXT_MUTED};margin-bottom:12px;">'
            f'Upload a CSV file with columns: <code>type, value, source, context</code></div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="batch-section">', unsafe_allow_html=True)
        uploaded = st.file_uploader("Choose file", type=["csv", "json"], label_visibility="collapsed")
        if uploaded:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploaded_" + uploaded.name if uploaded.name else "batch.csv")
            with open(path, "wb") as f:
                f.write(uploaded.getbuffer())
            with st.spinner("Processing batch…"):
                try:
                    batch_results = list(orchestrator.process_file(path))
                    for r in batch_results:
                        st.markdown(build_result_card(r), unsafe_allow_html=True)
                    st.success(f"✅ Processed {len(batch_results)} IOC(s) from {uploaded.name}")
                    os.remove(path)
                except Exception as e:
                    st.error(f"Batch processing failed: {e}")
        st.markdown('</div>', unsafe_allow_html=True)

    # ── Footer ──
    st.markdown(
        f'<div class="footer">IOC Enrichment Pipeline · '
        f'<a href="https://github.com/Tamerktb/ioc-enrichment-pipeline" target="_blank">GitHub</a>'
        f'</div>',
        unsafe_allow_html=True,
    )
