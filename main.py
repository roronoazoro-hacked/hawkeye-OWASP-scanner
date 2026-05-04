import uuid
import os
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from scanner import Scanner

app     = Flask(__name__, template_folder="templates")
scanner = Scanner()

# ── Auth config ──────────────────────────────────────────────────
# Change these to whatever you want
USERNAME = "admin"
PASSWORD = "root"

# Secret key signs the session cookie — change this to any long random string
app.secret_key = "change-this-to-a-long-random-secret-key-1234"


def login_required(f):
    """Decorator that redirects to /login if the user is not authenticated."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            # For API calls return 401, for page requests redirect to login
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorised"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Auth routes ──────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if (request.form.get("username") == USERNAME and
                request.form.get("password") == PASSWORD):
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── App routes (all protected) ───────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
@login_required
def start_scan():
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    mode = data.get("mode", "passive")
    if mode not in ("passive", "active"):
        mode = "passive"

    scan_id = str(uuid.uuid4()).replace("-", "")[:16]
    scanner.start_scan(scan_id, url, mode)
    return jsonify({"scan_id": scan_id, "mode": mode})

@app.route("/api/scan/<scan_id>")
@login_required
def get_scan(scan_id):
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)

@app.route("/api/scans")
@login_required
def get_all_scans():
    return jsonify(scanner.get_all_scans())

@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(scan_id):
    ok = scanner.cancel_scan(scan_id)
    if not ok:
        return jsonify({"error": "Scan not found or already complete"}), 404
    return jsonify({"ok": True, "scan_id": scan_id, "status": "cancelled"})

@app.route("/api/scan/<scan_id>/triage", methods=["POST"])
@login_required
def triage_finding(scan_id):
    data   = request.get_json()
    index  = data.get("index")
    status = data.get("status")
    valid  = {"Confirmed", "False Positive", "Accepted Risk", "Unreviewed"}
    if status not in valid:
        return jsonify({"error": "Invalid status"}), 400
    ok = scanner.triage_finding(scan_id, index, status)
    if not ok:
        return jsonify({"error": "Scan or finding not found"}), 404
    return jsonify({"ok": True, "index": index, "status": status})

@app.route("/api/scan/<scan_id>/report/pdf")
@login_required
def report_pdf(scan_id):
    from reporter import generate_pdf
    from flask import send_file
    import io
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    buf = generate_pdf(scan)
    return send_file(io.BytesIO(buf), mimetype="application/pdf",
                     as_attachment=True, download_name=f"report_{scan_id}.pdf")
    
@app.route("/api/scan/<scan_id>/export/csv")
@login_required
def export_csv_route(scan_id):
    from reporter import export_csv as _export_csv
    from flask import send_file
    import io
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    buf = _export_csv(scan)
    return send_file(io.BytesIO(buf.encode()),
                     mimetype="text/csv",
                     as_attachment=True,
                     download_name=f"report_{scan_id}.csv")

@app.route("/api/scan/<scan_id>/export/json")
@login_required
def export_json_route(scan_id):
    from reporter import export_json as _export_json
    from flask import send_file
    import io
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    buf = _export_json(scan)
    return send_file(io.BytesIO(buf.encode()), mimetype="application/json",
                     as_attachment=True, download_name=f"report_{scan_id}.json")

@app.route("/api/scan/<scan_id>/export/sarif")
@login_required
def export_sarif_route(scan_id):
    from reporter import export_sarif as _export_sarif
    from flask import send_file
    import io
    scan = scanner.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    buf = _export_sarif(scan)
    return send_file(io.BytesIO(buf.encode()), mimetype="application/json",
                     as_attachment=True, download_name=f"report_{scan_id}.sarif")
    
@app.route("/api/settings/webhook", methods=["GET"])
@login_required
def get_webhook():
    import scanner as _scanner
    return jsonify({"webhook_url": _scanner.get_webhook()})

@app.route("/api/settings/webhook", methods=["POST"])
@login_required
def set_webhook():
    import scanner as _scanner
    data = request.get_json()
    url  = data.get("url", "").strip()
    _scanner.set_webhook(url)
    return jsonify({"ok": True, "webhook_url": url})

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  OWASP Web Vulnerability Scanner")
    print("  Open: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)