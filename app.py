from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
from pathlib import Path
from datetime import datetime
import json, csv, io, html

HOST, PORT = "127.0.0.1", 5000
DATA_FILE = Path(__file__).resolve().parent / "incidents.json"
SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["Open", "Investigating", "Resolved", "Closed"]
CATEGORIES = ["Account Security", "Malware", "Phishing", "Network", "Lost Device", "Other"]

def load_incidents():
    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_incidents(incidents):
    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=2)

def next_id(incidents):
    return max((item.get("id", 0) for item in incidents), default=0) + 1

def esc(value):
    return html.escape(str(value or ""), quote=True)

def page(incidents, query="", status_filter="All", message=""):
    query_lower = query.lower()
    filtered = []
    for item in incidents:
        searchable = " ".join(str(item.get(k, "")) for k in ("title", "category", "severity", "status", "description")).lower()
        if query_lower and query_lower not in searchable:
            continue
        if status_filter != "All" and item.get("status") != status_filter:
            continue
        filtered.append(item)

    def options(values, selected=None):
        return "".join(f'<option value="{esc(v)}" {"selected" if v == selected else ""}>{esc(v)}</option>' for v in values)

    rows = []
    for item in filtered:
        ident = int(item.get("id", 0))
        rows.append(f"""<tr>
<td>IR-{ident:04d}</td>
<td><strong>{esc(item.get('title'))}</strong><div class="muted">{esc(item.get('description'))}</div></td>
<td>{esc(item.get('category'))}</td>
<td><span class="pill {esc(item.get('severity','').lower())}">{esc(item.get('severity'))}</span></td>
<td><form method="post" action="/update" class="inline"><input type="hidden" name="id" value="{ident}"><select name="status">{options(STATUSES, item.get('status'))}</select><button class="small">Save</button></form></td>
<td>{esc(item.get('created_at'))}</td></tr>""")
    rows_html = "\n".join(rows) if rows else '<tr><td colspan="6" class="empty">No incidents match your filters.</td></tr>'
    message_html = f'<div class="notice">{esc(message)}</div>' if message else ""
    open_count = sum(1 for x in incidents if x.get("status") == "Open")
    investigating_count = sum(1 for x in incidents if x.get("status") == "Investigating")
    critical_count = sum(1 for x in incidents if x.get("severity") == "Critical" and x.get("status") not in ("Resolved", "Closed"))
    resolved_count = sum(1 for x in incidents if x.get("status") in ("Resolved", "Closed"))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini Security Incident Reporter</title><style>
:root{{--navy:#13243a;--blue:#2864dc;--bg:#f3f6fb;--line:#dce3ee;--muted:#637087}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:#1b2638;font-family:Segoe UI,Arial,sans-serif}}
header{{background:var(--navy);color:white;padding:26px max(22px,calc((100% - 1180px)/2))}}header h1{{margin:0 0 6px;font-size:26px}}header p{{margin:0;color:#d1dced}}
main{{max-width:1180px;margin:24px auto;padding:0 18px 40px}}.stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}}
.stat,.panel{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 3px 12px #172b4d08}}
.label{{color:var(--muted);font-size:13px}}.number{{font-size:28px;font-weight:700;margin-top:7px}}
.layout{{display:grid;grid-template-columns:330px minmax(0,1fr);gap:18px;align-items:start}}h2{{font-size:18px;margin:0 0 16px}}
label{{display:block;font-size:13px;font-weight:600;margin:12px 0 6px}}input,select,textarea{{width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:7px;background:white;color:#1b2638;font:inherit}}textarea{{min-height:86px;resize:vertical}}
button,.button{{border:0;border-radius:7px;background:var(--blue);color:white;padding:10px 13px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}}.small{{padding:7px 9px;font-size:12px}}
.actions{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}.filters{{display:grid;grid-template-columns:minmax(150px,1fr) 150px auto;gap:8px;margin-bottom:14px}}
.table-wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{text-align:left;border-bottom:1px solid #e7ebf2;padding:12px 9px;vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.muted{{color:var(--muted);font-size:12px;margin-top:5px;line-height:1.4;max-width:290px}}.pill{{display:inline-block;padding:4px 8px;border-radius:20px;background:#e9eef7;font-size:12px;white-space:nowrap}}.pill.low{{background:#e0f5e9}}.pill.medium{{background:#fff0c2}}.pill.high{{background:#ffe0ce}}.pill.critical{{background:#ffd9df}}
.inline{{display:flex;gap:5px;min-width:145px}}.inline select{{padding:6px;min-width:0}}.notice{{padding:11px 13px;border-radius:8px;background:#e5f2ff;margin-bottom:14px}}.empty{{color:var(--muted);text-align:center;padding:26px}}footer{{color:var(--muted);font-size:12px;margin-top:18px}}
@media(max-width:850px){{.layout{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}@media(max-width:560px){{.filters{{grid-template-columns:1fr}}header h1{{font-size:22px}}}}
</style></head><body><header><h1>Mini Security Incident Reporter</h1><p>Local training dashboard </p></header><main>
{message_html}<section class="stats">
<div class="stat"><div class="label">Total incidents</div><div class="number">{len(incidents)}</div></div>
<div class="stat"><div class="label">Open</div><div class="number">{open_count}</div></div>
<div class="stat"><div class="label">Investigating</div><div class="number">{investigating_count}</div></div>
<div class="stat"><div class="label">Unresolved critical</div><div class="number">{critical_count}</div></div></section>
<div class="layout"><section class="panel"><h2>Report an incident</h2><form method="post" action="/add">
<label for="title">Incident title *</label><input id="title" name="title" maxlength="100" required>
<label for="category">Category</label><select id="category" name="category">{options(CATEGORIES)}</select>
<label for="severity">Severity</label><select id="severity" name="severity">{options(SEVERITIES, "Medium")}</select>
<label for="description">Description *</label><textarea id="description" name="description" maxlength="1000" required></textarea>
<button type="submit" style="margin-top:14px;width:100%">Add incident</button></form>
<footer>Use fictional training data only. Do not enter real passwords or confidential information.</footer></section>
<section class="panel"><div class="actions" style="justify-content:space-between;margin-bottom:14px"><h2 style="margin:0">Incident log</h2><a class="button" href="/export.csv">Export CSV</a></div>
<form method="get" action="/" class="filters"><input name="q" value="{esc(query)}" placeholder="Search incidents..."><select name="status">{options(["All"]+STATUSES,status_filter)}</select><button>Filter</button></form>
<div class="table-wrap"><table><thead><tr><th>ID</th><th>Incident</th><th>Category</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead><tbody>{rows_html}</tbody></table></div>
<footer>Resolved/closed incidents: {resolved_count}. Data is stored in incidents.json on this computer.</footer></section></div></main></body></html>"""

class IncidentHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200):
        payload = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect_message(self, message):
        self.send_response(303)
        self.send_header("Location", "/?message=" + quote(message))
        self.end_headers()

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return {key: values[0] for key, values in parse_qs(raw, keep_blank_values=True).items()}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/export.csv":
            output = io.StringIO(newline="")
            fields = ["id", "title", "category", "severity", "status", "description", "created_at"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for item in load_incidents():
                writer.writerow({key: item.get(key, "") for key in fields})
            data = output.getvalue().encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="incidents.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path != "/":
            self.send_html("<h1>404 - Page not found</h1><p><a href='/'>Back to dashboard</a></p>", 404)
            return
        params = parse_qs(parsed.query)
        query = params.get("q", [""])[0][:100]
        status_filter = params.get("status", ["All"])[0]
        if status_filter not in ["All"] + STATUSES:
            status_filter = "All"
        self.send_html(page(load_incidents(), query, status_filter, params.get("message", [""])[0][:200]))

    def do_POST(self):
        parsed = urlparse(self.path)
        form = self.read_form()
        incidents = load_incidents()
        if parsed.path == "/add":
            title = form.get("title", "").strip()[:100]
            description = form.get("description", "").strip()[:1000]
            category = form.get("category", "Other")
            severity = form.get("severity", "Medium")
            if not title or not description:
                self.redirect_message("Please provide a title and description.")
                return
            if category not in CATEGORIES or severity not in SEVERITIES:
                self.redirect_message("Please select a valid category and severity.")
                return
            incidents.append({"id": next_id(incidents), "title": title, "category": category, "severity": severity,
                "status": "Open", "description": description, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
            save_incidents(incidents)
            self.redirect_message("Incident added successfully.")
            return
        if parsed.path == "/update":
            try:
                incident_id = int(form.get("id", ""))
            except ValueError:
                self.redirect_message("Invalid incident ID.")
                return
            new_status = form.get("status", "")
            if new_status not in STATUSES:
                self.redirect_message("Please select a valid status.")
                return
            for item in incidents:
                if item.get("id") == incident_id:
                    item["status"] = new_status
                    save_incidents(incidents)
                    self.redirect_message("Incident status updated.")
                    return
            self.redirect_message("Incident not found.")
            return
        self.send_html("<h1>404 - Page not found</h1><p><a href='/'>Back to dashboard</a></p>", 404)

    def log_message(self, format_string, *args):
        print("%s - %s" % (self.address_string(), format_string % args))

if __name__ == "__main__":
    if not DATA_FILE.exists():
        save_incidents([])
    server = ThreadingHTTPServer((HOST, PORT), IncidentHandler)
    print("Mini Security Incident Reporter is running.")
    print(f"Open http://{HOST}:{PORT} in your browser.")
    print("Keep this window open while using the dashboard.")
    print("Press Ctrl+C to stop the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
