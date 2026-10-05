"""Flask dashboard that reads the NetSight database and serves the web UI."""

import csv
import io
import os
import sqlite3

from flask import Flask, jsonify, render_template, send_file, abort


def create_app(db_path="netsight.db", pcap_path="forensic.pcap"):
    app = Flask(__name__)

    def query(sql, args=()):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, args).fetchall()
        conn.close()
        return rows

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def stats():
        categories = {r["category"]: r["c"]
                      for r in query("SELECT category, COUNT(*) c FROM alerts GROUP BY category")}
        severities = {r["severity"]: r["c"]
                      for r in query("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")}
        timeline = [[int(r["bucket"]), r["c"]] for r in query(
            "SELECT CAST(ts AS INTEGER)/5*5 AS bucket, COUNT(*) c "
            "FROM alerts GROUP BY bucket ORDER BY bucket")]
        total_packets = query("SELECT COUNT(*) c FROM packets")[0]["c"]
        total_alerts = query("SELECT COUNT(*) c FROM alerts")[0]["c"]
        return jsonify(categories=categories, severities=severities,
                       timeline=timeline, total_packets=total_packets,
                       total_alerts=total_alerts)

    @app.route("/api/alerts")
    def alerts():
        rows = query("SELECT * FROM alerts ORDER BY ts DESC LIMIT 300")
        return jsonify([dict(r) for r in rows])

    @app.route("/export/report")
    def export_report():
        rows = query("SELECT * FROM alerts ORDER BY ts")
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        fields = ["ts", "category", "severity", "src", "dst",
                  "sport", "dport", "proto", "description"]
        writer.writerow(fields)
        for row in rows:
            writer.writerow([row[f] for f in fields])
        data = io.BytesIO(buffer.getvalue().encode())
        data.seek(0)
        return send_file(data, as_attachment=True,
                         download_name="netsight_incident_report.csv",
                         mimetype="text/csv")

    @app.route("/export/pcap")
    def export_pcap():
        if not os.path.exists(pcap_path):
            abort(404, "No forensic capture available yet.")
        return send_file(pcap_path, as_attachment=True,
                         download_name="netsight_forensic.pcap")

    return app
