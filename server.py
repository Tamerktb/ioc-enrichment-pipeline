"""
IOC Enrichment Pipeline — Flask API Server
Serves the live frontend and handles enrichment API calls.
"""
import sys
import os
import json
import io
import csv
import logging
from pathlib import Path
from functools import wraps
from datetime import datetime

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from flask import (
        Flask, send_from_directory, request, jsonify,
    )
    import yaml
    from dotenv import load_dotenv
except ImportError:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

from pipeline.orchestrator import PipelineOrchestrator
from pipeline.ioc_parser import IOC, IOCParser

load_dotenv()

# ── Config ──
config = {}
if os.path.exists("config.yaml"):
    with open("config.yaml") as f:
        config = yaml.safe_load(f) or {}

orchestrator = PipelineOrchestrator(config)

TOOL_NAMES = ["ipinfo", "abuseipdb", "virustotal"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("server")

# ── Flask app ──
app = Flask(__name__, static_folder=None)  # We'll serve index.html manually

STATIC_DIR = os.path.dirname(os.path.abspath(__file__))


# ═══════════════════════════════════════════════════════════════════════════════
# API: Enrich a single IOC
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    data = request.get_json(silent=True)
    if not data or "ioc" not in data:
        return jsonify({"error": "Missing 'ioc' field in request body"}), 400

    ioc_value = data["ioc"].strip()
    if not ioc_value:
        return jsonify({"error": "IOC value cannot be empty"}), 400

    try:
        detected = IOCParser.detect_type(ioc_value)
        ioc = IOC(type=detected, value=ioc_value)
        result = orchestrator.process_ioc(ioc)
        return jsonify(serialize_result(result))
    except ValueError as e:
        return jsonify({"error": f"Could not process: {e}"}), 400
    except Exception as e:
        logger.error(f"Enrichment error: {e}")
        return jsonify({"error": f"Internal error: {e}"}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# API: Batch enrich from uploaded file
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/batch", methods=["POST"])
def api_batch():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    try:
        content = file.read().decode("utf-8")
        ext = os.path.splitext(file.filename)[1].lower()

        if ext == ".csv":
            iocs = IOCParser.parse_csv(content)
        elif ext == ".json":
            iocs = IOCParser.parse_json(json.loads(content))
        elif ext == ".txt":
            iocs = []
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    iocs.append(IOCParser.parse_single(line))
                except ValueError:
                    continue
        else:
            return jsonify({"error": f"Unsupported format: {ext}. Use .csv, .json, or .txt"}), 400

        if not iocs:
            return jsonify({"error": "No valid IOCs found in file"}), 400

        results = orchestrator.process_iocs(iocs)
        return jsonify({
            "count": len(results),
            "results": [serialize_result(r) for r in results],
        })
    except Exception as e:
        logger.error(f"Batch error: {e}")
        return jsonify({"error": f"Batch processing failed: {e}"}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# API: Status / tool info
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/status", methods=["GET"])
def api_status():
    tools = []
    for name in TOOL_NAMES:
        has_key = name == "ipinfo" or bool(os.getenv(f"{name.upper()}_API_KEY", ""))
        tool_obj = orchestrator.manager._tools.get(name)
        tools.append({
            "name": name,
            "description": tool_obj.description if tool_obj else "",
            "ready": has_key,
        })

    try:
        cache_stats = orchestrator.cache.stats()
    except Exception:
        cache_stats = {"total_entries": 0, "hit_rate": 0}

    return jsonify({
        "tools": tools,
        "cache": cache_stats,
        "version": "1.0.0",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# Serve the frontend
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def serve_index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(STATIC_DIR, path)


# ═══════════════════════════════════════════════════════════════════════════════
# Result serializer — converts PipelineOrchestrator result to JSON-safe dict
# ═══════════════════════════════════════════════════════════════════════════════
def serialize_result(result: dict) -> dict:
    ioc = result["ioc"]
    score = result.get("score", {})
    raw_results = result.get("results", {})

    # Serialize IOC
    ioc_data = {
        "type": ioc.type.upper(),
        "value": ioc.value,
        "source": ioc.source,
        "context": ioc.context,
    }

    # Serialize score
    score_data = {
        "score": round(score.get("score", 0), 1),
        "severity": score.get("severity", "none"),
        "confidence": score.get("confidence", 0),
        "summary": score.get("summary", ""),
    }

    # Serialize per-tool results — only include successful ones
    tools_data = {}
    for name in TOOL_NAMES:
        tr = raw_results.get(name, {})
        if not tr.get("success") or not tr.get("data"):
            continue
        data = tr["data"]
        # Skip tools that only returned a "note" (gracefully skipped)
        if list(data.keys()) == ["note"]:
            continue

        cells = []
        if name == "ipinfo":
            loc = ", ".join(filter(None, [data.get("city"), data.get("region"), data.get("country")]))
            risk = data.get("high_risk_country")
            location_text = loc or "Unknown"
            if risk:
                location_text += " ⚠️ High-risk"
            cells = [
                ("📍 Location", location_text),
                ("🌐 ISP", data.get("isp", "—")),
                ("🔢 ASN", data.get("asn", "—")),
                ("🏳️ Country", data.get("country", "—")),
                ("🕐 Timezone", data.get("timezone", "—")),
                ("🖥️ Hostname", data.get("hostname") or "—"),
            ]
        elif name == "abuseipdb":
            cells = [
                ("⚠️ Abuse Score", f"{data.get('abuse_confidence_score', 0)}/100"),
                ("📋 Reports", str(data.get("total_reports", 0))),
                ("👥 Distinct Users", str(data.get("num_distinct_users", 0))),
                ("🏳️ Country", data.get("country_name", "—")),
                ("🏢 ISP", data.get("isp", "—")),
                ("📅 Last Reported", str(data.get("last_reported_at") or "—")),
            ]
        elif name == "virustotal":
            cells = [
                ("🦠 Malicious", f"{data.get('malicious_detections', 0)}/{data.get('total_engines', 0)}"),
                ("⚠️ Suspicious", str(data.get("suspicious_detections", 0))),
                ("✅ Clean", str(data.get("harmless", 0))),
            ]
            if data.get("country"):
                cells.append(("🏳️ Country", data["country"]))
            if data.get("note"):
                cells.append(("ℹ️ Note", data["note"]))

        tools_data[name] = {
            "cells": cells,
            "success": tr.get("success", False),
            "error": tr.get("error"),
            "latency": tr.get("latency", 0),
        }

    # Tool status for the footer row
    tool_status = {}
    for name in TOOL_NAMES:
        tr = raw_results.get(name, {})
        if tr.get("success") and tr.get("data"):
            tool_status[name] = "ok" if list(tr["data"].keys()) != ["note"] else "warn"
        elif tr.get("error"):
            tool_status[name] = "err"
        else:
            tool_status[name] = "warn"

    return {
        "ioc": ioc_data,
        "score": score_data,
        "tools": tools_data,
        "tool_status": tool_status,
        "elapsed": result.get("elapsed", 0),
        "was_cached": result.get("was_cached", False),
        "llm_summary": result.get("llm_summary"),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    logger.info(f"Starting IOC Enrichment server on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)