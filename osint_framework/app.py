from flask import Flask, render_template, request, jsonify, send_file
import csv, json, io, os, sys

# Add project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

import db
import scanner
import risk

app = Flask(__name__)

db.init_db()

# Allowed scan types
# people = name/person discovery
# username = username/social scan
# email = email/breach/web scan
# domain = WHOIS/DNS/IP scan
# ip = IP geolocation scan
# phone = phone validation/web phone discovery
TARGET_TYPES = ["people", "username", "email", "domain", "ip", "phone"]


# ─────────────────────────────────────────────
# FRONTEND PAGES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    scans = db.get_all_scans()
    return render_template(
        "index.html",
        scans=scans,
        target_types=TARGET_TYPES
    )


@app.route("/scan/<int:scan_id>")
def scan_view(scan_id):
    scan = db.get_scan(scan_id)

    if not scan:
        return "Scan not found", 404

    results = db.get_results(scan_id)
    summary = db.get_result_summary(scan_id)
    modules = db.get_modules_used(scan_id)
    risk_score = risk.calculate_risk(results)

    return render_template(
        "scan.html",
        scan=scan,
        results=results,
        summary=summary,
        modules=modules,
        risk=risk_score
    )


@app.route("/scan/<int:scan_id>/graph")
def graph_view(scan_id):
    scan = db.get_scan(scan_id)

    if not scan:
        return "Scan not found", 404

    return render_template("graph.html", scan=scan)


@app.route("/scan/<int:scan_id>/map")
def map_view(scan_id):
    scan = db.get_scan(scan_id)

    if not scan:
        return "Scan not found", 404

    return render_template("map.html", scan=scan)


# ─────────────────────────────────────────────
# API
# ─────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def api_start():
    data = request.get_json() or {}

    target = (data.get("target") or "").strip()
    target_type = (data.get("target_type") or "").strip()

    # Supports multi-select from updated index.html
    # Example:
    # {
    #   "target": "john smith",
    #   "target_type": "people",
    #   "target_types": ["people", "username", "email", "phone"]
    # }
    target_types = data.get("target_types") or [target_type]

    if not isinstance(target_types, list):
        target_types = [target_type]

    target_types = [
        str(t).strip()
        for t in target_types
        if str(t).strip()
    ]

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if not target_types:
        return jsonify({"error": "Select at least one scan type"}), 400

    for t in target_types:
        if t not in TARGET_TYPES:
            return jsonify({"error": f"Invalid scan type: {t}"}), 400

    # First selected type is used as the primary display type
    target_type = target_types[0]

    try:
        scan_id = scanner.start_scan(
            target=target,
            target_type=target_type,
            target_types=target_types
        )
    except TypeError:
        # Fallback for old scanner.py that only accepts target and target_type
        # Update scanner.py later for full multi-select support.
        scan_id = scanner.start_scan(target, target_type)

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<int:scan_id>/progress")
def api_progress(scan_id):
    return jsonify(scanner.get_progress(scan_id))


@app.route("/api/scan/<int:scan_id>/results")
def api_results(scan_id):
    data_type = request.args.get("data_type")
    module = request.args.get("module")

    results = db.get_results(
        scan_id,
        data_type=data_type,
        module=module
    )

    summary = db.get_result_summary(scan_id)
    modules = db.get_modules_used(scan_id)
    risk_score = risk.calculate_risk(results)

    return jsonify({
        "results": results,
        "summary": summary,
        "modules": modules,
        "risk": risk_score
    })


@app.route("/api/scan/<int:scan_id>/map-data")
def api_map_data(scan_id):
    import re
    import requests as req

    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    results = db.get_results(scan_id)
    locations = []

    LOCATION_TYPES = {
        "location", "country", "city", "region",
        "address", "work_location", "ip_location",
        "geo", "coordinates", "timezone"
    }

    SKIP_VALUES = {"unknown", "n/a", "none", "null", "", "private", "reserved"}
    SKIP_PATTERNS = [
        r"^[A-Za-z]+/[A-Za-z_]+$",   # timezone like America/New_York
        r"^https?://",                 # URLs
        r"^\d+%",                      # percentages
    ]

    def parse_coords(s):
        """Parse '37.77, -122.41' → (lat, lon) or None"""
        m = re.match(r"^(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)$", s.strip())
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return lat, lon
        return None

    def geocode(label):
        """Server-side Nominatim geocode — no CORS issues"""
        try:
            r = req.get(
                "https://nominatim.openstreetmap.org/search",
                params={"format": "json", "limit": 1, "q": label},
                headers={"User-Agent": "OSINT-Framework/1.0"},
                timeout=8
            )
            data = r.json()
            if data:
                return float(data[0]["lat"]), float(data[0]["lon"])
        except Exception:
            pass
        return None

    seen = set()

    for r in results:
        data_type = str(r.get("data_type", "")).lower()
        value     = str(r.get("value", "")).strip()

        if not value or data_type not in LOCATION_TYPES:
            continue
        if value.lower() in SKIP_VALUES:
            continue
        if any(re.search(p, value, re.I) for p in SKIP_PATTERNS):
            continue
        if value in seen:
            continue
        seen.add(value)

        entry = {
            "label":  value,
            "type":   data_type,
            "source": r.get("source", ""),
            "module": r.get("module", ""),
            "lat":    None,
            "lon":    None,
        }

        # 1. Direct coordinate string — instant, no API call
        coords = parse_coords(value)
        if coords:
            entry["lat"], entry["lon"] = coords
        else:
            # 2. Server-side geocode via Nominatim
            result = geocode(value)
            if result:
                entry["lat"], entry["lon"] = result

        locations.append(entry)

    return jsonify({"scan": scan, "locations": locations})


@app.route("/api/scan/<int:scan_id>/graph-data")
def api_graph(scan_id):
    scan = db.get_scan(scan_id)

    if not scan:
        return jsonify({"error": "not found"}), 404

    results = db.get_results(scan_id)

    nodes = [{
        "id": "target",
        "label": scan["target"],
        "type": "target",
        "group": "target",
        "size": 36
    }]

    edges = []
    seen_edges = set()

    # Module nodes
    modules_seen = list({
        r.get("module", "unknown")
        for r in results
        if r.get("module")
    })

    for mod in modules_seen:
        mod_id = f"mod:{mod}"

        nodes.append({
            "id": mod_id,
            "label": mod,
            "type": "module",
            "group": mod,
            "size": 22
        })

        edge_id = f"target->{mod_id}"

        if edge_id not in seen_edges:
            edges.append({
                "from": "target",
                "to": mod_id,
                "type": "module_link"
            })
            seen_edges.add(edge_id)

    # Result nodes
    SKIP_TYPES = {
        "error",
        "not_found",
        "stat",
        "account_detail"
    }

    for r in results:
        data_type = str(r.get("data_type", "")).lower()

        if data_type in SKIP_TYPES:
            continue

        value = str(r.get("value", ""))

        if not value:
            continue

        label = value[:60] + ("…" if len(value) > 60 else "")

        res_id = f"res:{r.get('id')}"
        mod_id = f"mod:{r.get('module', 'unknown')}"

        nodes.append({
            "id": res_id,
            "label": label,
            "full": value,
            "type": data_type,
            "group": data_type,
            "module": r.get("module", ""),
            "source": r.get("source", ""),
            "size": 14
        })

        edge_id = f"{mod_id}->{res_id}"

        if edge_id not in seen_edges:
            edges.append({
                "from": mod_id,
                "to": res_id,
                "type": "result_link"
            })
            seen_edges.add(edge_id)

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "scan": scan
    })


@app.route("/api/scan/<int:scan_id>/stop", methods=["POST"])
def api_stop(scan_id):
    scanner.stop_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/scan/<int:scan_id>/delete", methods=["DELETE"])
def api_delete(scan_id):
    db.delete_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/scan/<int:scan_id>/export")
def api_export(scan_id):
    fmt = request.args.get("fmt", "json")

    results = db.get_results(scan_id)
    scan = db.get_scan(scan_id)

    if not scan:
        return jsonify({"error": "not found"}), 404

    if fmt == "csv":
        out = io.StringIO()

        writer = csv.DictWriter(
            out,
            fieldnames=["module", "data_type", "value", "source"]
        )

        writer.writeheader()

        for r in results:
            writer.writerow({
                "module": r.get("module", ""),
                "data_type": r.get("data_type", ""),
                "value": r.get("value", ""),
                "source": r.get("source", "")
            })

        out.seek(0)

        return send_file(
            io.BytesIO(out.read().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"scan_{scan_id}.csv"
        )

    payload = {
        "scan": scan,
        "results": results
    }

    out = io.BytesIO(
        json.dumps(payload, indent=2).encode()
    )

    return send_file(
        out,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"scan_{scan_id}.json"
    )


@app.route("/api/scans")
def api_scans():
    return jsonify(db.get_all_scans())


# ─────────────────────────────────────────────
# RUN SERVER
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🕷️ OSINT Framework → http://localhost:5000\n")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        threaded=True
    )
