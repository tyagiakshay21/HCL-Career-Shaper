import re
from flask import Flask, render_template_string, request
import json
import os
import datetime

app = Flask(__name__)

# =========================================================
# SECRET PATTERNS
# =========================================================

SECRET_PATTERNS = [
    r"password=\S+",
    r"api_key=\S+",
    r"token=\S+"
]


# =========================================================
# FIND SECRETS
# =========================================================

def find_secrets(text):
    matches = []

    for pattern in SECRET_PATTERNS:
        found = re.findall(pattern, text, re.IGNORECASE)
        matches.extend(found)

    return matches


# =========================================================
# DETECTION LOGIC
# =========================================================

def detect_exposure(text, transport):
    secrets = find_secrets(text)

    insecure = transport.lower() == "http"

    if secrets and insecure:
        return {
            "alert": True,
            "reason": "Credential exposed over insecure HTTP",
            "matches": secrets
        }

    return {
        "alert": False,
        "reason": "No insecure credential exposure detected",
        "matches": secrets
    }


# =========================================================
# FINDINGS FILE
# =========================================================

FINDINGS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "findings.json"
)


# =========================================================
# SAVE FINDING
# =========================================================

def save_finding(summary, severity="Info"):

    data = []

    if os.path.exists(FINDINGS_FILE):

        try:
            with open(FINDINGS_FILE, "r") as f:
                data = json.load(f)

        except (json.JSONDecodeError, FileNotFoundError):
            data = []

    data.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "summary": summary,
        "severity": severity
    })

    # Keep only the latest 50 findings
    data = data[-50:]

    with open(FINDINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)


# =========================================================
# REAL DETECTION: inspect every request that arrives at /login
# =========================================================

def mask(match):
    """password=abc123 -> password=********  (never store real secrets)"""
    return re.sub(r"=(.*)", "=********", match)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Raw request body + query string = exactly what a sniffer would see on the wire
    payload = request.get_data(as_text=True) + "&" + request.query_string.decode(errors="ignore")

    # Real transport of THIS request (honours a reverse proxy header if present)
    transport = request.headers.get("X-Forwarded-Proto", request.scheme)

    result = detect_exposure(payload, transport)
    masked = [mask(m) for m in result["matches"]]

    print("patterns:", SECRET_PATTERNS)
    print("transport:", transport.upper())
    print("Matched credentials:", masked)
    print("ALERT:", result["alert"])
    print("Reason:", result["reason"])

    if result["alert"]:
        found = ", ".join(m.split("=")[0] for m in masked)
        save_finding(
            f"{result['reason']} ({found}) from {request.remote_addr}",
            "High"
        )
    else:
        save_finding(result["reason"], "Info")

    return {"alert": result["alert"], "reason": result["reason"], "matches": masked}


# =========================================================
# DASHBOARD HTML
# =========================================================

DASH_HTML = """
<!DOCTYPE html>

<html>

<head>

    <title>Security Detection Dashboard</title>

    <meta charset="UTF-8">

    <meta http-equiv="refresh" content="5">

    <style>

        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background: #f4f6f8;
        }

        .header {
            background: #1F4E78;
            color: white;
            padding: 25px 40px;
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
        }

        .header p {
            margin-top: 8px;
            margin-bottom: 0;
        }

        .container {
            width: 90%;
            margin: 30px auto;
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        h2 {
            color: #333;
            margin-top: 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th {
            background: #1F4E78;
            color: white;
            padding: 14px;
            text-align: left;
        }

        td {
            padding: 14px;
            border-bottom: 1px solid #ddd;
        }

        tr:hover {
            background: #f5f5f5;
        }

        .severity {
            color: white;
            font-weight: bold;
            text-align: center;
            border-radius: 5px;
        }

        .empty {
            padding: 20px;
            background: #eeeeee;
            border-radius: 5px;
            color: #555;
        }

    </style>

</head>


<body>


<div class="header">

    <h1>Security Detection Dashboard</h1>

    <p>Live Sensitive Data Exposure Monitoring</p>

</div>


<div class="container">

    <h2>Live Findings <small style="font-size:13px;color:#888;font-weight:normal">(auto-refreshes every 5 s)</small></h2>


    {% if rows %}

    <table>

        <tr>

            <th>Time</th>

            <th>Finding</th>

            <th>Severity</th>

        </tr>


        {% for r in rows %}

        <tr>

            <td>
                {{ r.time }}
            </td>


            <td>
                {{ r.summary }}
            </td>


            <td
                class="severity"
                style="
                    background:
                    {% if r.severity == 'Critical' %}
                        #c0392b
                    {% elif r.severity == 'High' %}
                        #e74c3c
                    {% elif r.severity == 'Medium' %}
                        #f39c12
                    {% else %}
                        #95a5a6
                    {% endif %}
                "
            >

                {{ r.severity }}

            </td>

        </tr>

        {% endfor %}


    </table>


    {% else %}

        <div class="empty">

            No security findings detected yet.

        </div>

    {% endif %}


</div>


</body>

</html>
"""


# =========================================================
# DASHBOARD ROUTE
# =========================================================

@app.route("/dashboard")
def dashboard():

    rows = []

    if os.path.exists(FINDINGS_FILE):

        try:

            with open(FINDINGS_FILE, "r") as f:
                rows = json.load(f)

        except (json.JSONDecodeError, FileNotFoundError):

            rows = []

    # Newest finding first
    rows = list(reversed(rows))

    return render_template_string(
        DASH_HTML,
        rows=rows
    )


# =========================================================
# HOME ROUTE
# =========================================================

@app.route("/")
def home():

    return """
    <h1>Security Detection System</h1>

    <p>Detector is running successfully.</p>

    <p>Trigger a detection:<br>
    <code>curl -X POST -d "password=Fake123&amp;api_key=FAKE-KEY" http://localhost:5000/login</code></p>

    <p>
        <a href="/dashboard">
            Open Security Dashboard
        </a>
    </p>
    """


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )