# GRC Command Center

A self-contained Governance, Risk & Compliance management tool built with Python/Flask + SQLite.
No external database or account setup needed — it runs entirely on your machine.

## What it does

- **Dashboard** — KPIs, a Likelihood x Impact risk heat map, control implementation status, and a "needs attention" feed (overdue findings/policies/vendor reviews)
- **Risk Register** — add/edit/delete risks, auto-calculated inherent risk score (Likelihood x Impact) and residual risk after controls, CSV export
- **Control Mapping** — a starter set of controls mapped to **NIST CSF 2.0** functions (Govern, Identify, Protect, Detect, Respond, Recover), with status/owner/evidence tracking, CSV export
- **Vendor Risk** — third-party risk tiering with assessment due-date tracking and overdue flags
- **Audit Findings** — findings register with severity, remediation plans, owners, due dates, and status
- **Policies** — policy inventory with review cadence and overdue flags

It comes pre-loaded with realistic sample data (8 risks, 20 NIST CSF controls, 5 vendors, 5 audit findings, 6 policies) so it's immediately useful for a demo, portfolio project, or as a template for a real program.

## Requirements

- Python 3.9 or newer (nothing else — Flask is the only dependency)

## How to run it

1. **Unzip** the project folder and open a terminal in it.

2. **(Recommended) Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```

3. **Install the one dependency:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run it:**
   ```bash
   python3 app.py
   ```

5. Open your browser to **http://127.0.0.1:5050**

That's it. A `grc.db` SQLite file is created automatically on first run and pre-populated with sample data. Everything you add, edit, or delete through the UI is saved there.

## Resetting the data

Delete `grc.db` and restart the app — it will recreate the database and reseed the sample data.

## Project structure

```
grc-toolkit/
├── app.py                  # Flask app: routes, DB schema, seed data, risk scoring logic
├── requirements.txt
├── grc.db                  # created automatically on first run
├── templates/               # Jinja2 HTML templates (Bootstrap 5)
└── static/style.css         # UI styling
```

## Making it your own (ideas to extend it, good for interviews/portfolio talking points)

- Swap the NIST CSF 2.0 seed controls for **ISO 27001 Annex A** or **SOC 2 Trust Services Criteria**
- Add authentication (Flask-Login) and per-user ownership of risks/findings
- Add a risk trend chart over time (snapshot risk scores on a schedule)
- Generate a PDF board-ready report (e.g. with `reportlab` or `weasyprint`)
- Add email/Slack reminders for overdue policy reviews and vendor assessments
- Deploy it (Render, Fly.io, a small VPS) so it's a live link you can put on your resume/LinkedIn instead of just a local demo

## Why this is a useful GRC portfolio project

Most GRC portfolio pieces are static spreadsheets. This demonstrates you can actually operationalize a framework (NIST CSF 2.0 control mapping), quantify risk (likelihood x impact scoring with residual risk), run a vendor risk program, track audit remediation to closure, and manage policy lifecycle — all in a working tool you built and can talk through in an interview.
