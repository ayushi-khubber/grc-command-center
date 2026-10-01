"""
GRC Command Center
A self-contained Governance, Risk & Compliance management tool.
Risk register, control-framework mapping (NIST CSF 2.0), vendor risk,
audit findings tracking, and policy lifecycle management.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, Response
import sqlite3
import os
import csv
import io
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'grc.db')

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-me'

TODAY = datetime.today().date()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    fresh = not os.path.exists(DB_PATH)
    conn = get_db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS risks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT,
        description TEXT,
        likelihood INTEGER,
        impact INTEGER,
        owner TEXT,
        status TEXT,
        date_identified TEXT,
        mitigating_controls TEXT,
        residual_likelihood INTEGER,
        residual_impact INTEGER
    );
    CREATE TABLE IF NOT EXISTS controls (
        id TEXT PRIMARY KEY,
        function TEXT,
        category TEXT,
        description TEXT,
        status TEXT,
        owner TEXT,
        evidence TEXT,
        last_updated TEXT
    );
    CREATE TABLE IF NOT EXISTS vendors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        service TEXT,
        data_access TEXT,
        risk_tier TEXT,
        last_assessment TEXT,
        next_assessment TEXT,
        findings TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT NOT NULL,
        source TEXT,
        severity TEXT,
        control_ref TEXT,
        remediation_plan TEXT,
        owner TEXT,
        due_date TEXT,
        status TEXT
    );
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT,
        version TEXT,
        owner TEXT,
        last_review TEXT,
        next_review TEXT,
        status TEXT
    );
    ''')
    conn.commit()
    if fresh:
        seed_data(conn)
    conn.close()


def seed_data(conn):
    c = conn.cursor()

    risks = [
        ("Ransomware attack on production servers", "Cyber", "Threat actor encrypts production systems via phishing-delivered payload, disrupting operations.", 3, 5, "CISO", "Open", "2026-01-12", "EDR deployment, backup isolation, security awareness training", 2, 4),
        ("Unpatched critical vulnerabilities in externally facing assets", "Cyber", "Delayed patch cycles leave internet-facing systems exposed to known CVEs.", 4, 4, "IT Ops Manager", "Open", "2026-02-03", "Vulnerability management program, patch SLAs", 2, 3),
        ("Third-party vendor data breach", "Third-Party", "A critical vendor with access to customer PII suffers a breach affecting shared data.", 3, 5, "Vendor Risk Manager", "Open", "2026-01-20", "Vendor due diligence, DPA clauses, annual assessments", 2, 4),
        ("Non-compliance with data residency requirements", "Compliance", "Customer data processed outside contractually agreed jurisdictions.", 2, 4, "Compliance Officer", "Open", "2025-12-10", "Data mapping, cloud region controls", 1, 3),
        ("Insider misuse of privileged access", "Operational", "Employee with elevated access exfiltrates or misuses sensitive data.", 2, 5, "IT Security Manager", "Open", "2026-03-01", "Least privilege, access reviews, DLP", 1, 4),
        ("Loss of key person / undocumented processes", "Operational", "Critical process knowledge concentrated in one employee with no succession plan.", 3, 3, "COO", "Open", "2026-01-05", "Process documentation, cross-training", 2, 2),
        ("Inadequate incident response readiness", "Cyber", "IR plan untested; response times and communication breakdown during real incident.", 3, 4, "CISO", "In Progress", "2026-02-15", "Tabletop exercises, IR plan updates", 2, 3),
        ("GDPR/CCPA non-compliance in data subject request handling", "Data Privacy", "Failure to respond to data subject access/deletion requests within regulatory timelines.", 2, 4, "DPO", "Open", "2026-01-28", "DSR workflow tooling, staff training", 1, 3),
    ]
    c.executemany('''INSERT INTO risks
        (title, category, description, likelihood, impact, owner, status, date_identified,
         mitigating_controls, residual_likelihood, residual_impact)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''', risks)

    controls = [
        ("GV.OC-01", "Govern", "Organizational Context", "The organizational mission is understood and informs cybersecurity risk management", "Implemented", "CISO", "Board charter, risk appetite statement", "2026-06-01"),
        ("GV.RM-01", "Govern", "Risk Management Strategy", "Risk management objectives are established and agreed to by stakeholders", "Implemented", "Risk Committee", "Risk management policy v3", "2026-05-15"),
        ("GV.PO-01", "Govern", "Policy", "Cybersecurity policy is established and communicated", "Implemented", "CISO", "Policy repository, acknowledgement logs", "2026-04-20"),
        ("GV.SC-01", "Govern", "Supply Chain Risk Mgmt", "A cybersecurity supply chain risk management program is established", "In Progress", "Vendor Risk Manager", "Vendor risk program draft", "2026-06-10"),
        ("ID.AM-01", "Identify", "Asset Management", "Inventories of hardware managed by the organization are maintained", "Implemented", "IT Ops Manager", "CMDB export", "2026-06-05"),
        ("ID.AM-02", "Identify", "Asset Management", "Inventories of software, services, and systems are maintained", "In Progress", "IT Ops Manager", "SaaS inventory spreadsheet", "2026-06-05"),
        ("ID.RA-01", "Identify", "Risk Assessment", "Vulnerabilities in assets are identified and documented", "Implemented", "Security Engineer", "Vulnerability scan reports", "2026-06-08"),
        ("ID.RA-05", "Identify", "Risk Assessment", "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk", "Implemented", "Risk Analyst", "Risk register", "2026-06-08"),
        ("PR.AA-01", "Protect", "Identity Mgmt & Access Control", "Identities and credentials for authorized users are managed", "Implemented", "IAM Lead", "IAM audit logs", "2026-05-30"),
        ("PR.AA-05", "Protect", "Identity Mgmt & Access Control", "Access permissions are defined per least privilege and separation of duties", "In Progress", "IAM Lead", "Access review Q2 2026", "2026-06-01"),
        ("PR.AT-01", "Protect", "Awareness & Training", "Personnel are provided cybersecurity awareness training", "Implemented", "Security Awareness Lead", "Training completion records", "2026-03-15"),
        ("PR.DS-01", "Protect", "Data Security", "Data-at-rest is protected", "Implemented", "IT Security Manager", "Encryption standards doc", "2026-04-01"),
        ("PR.DS-02", "Protect", "Data Security", "Data-in-transit is protected", "Implemented", "IT Security Manager", "TLS configuration audit", "2026-04-01"),
        ("PR.PS-01", "Protect", "Platform Security", "Configuration management practices are established", "In Progress", "IT Ops Manager", "Hardening baseline draft", "2026-06-12"),
        ("DE.CM-01", "Detect", "Continuous Monitoring", "Networks and network services are monitored for anomalous activity", "Implemented", "SOC Manager", "SIEM dashboards", "2026-06-11"),
        ("DE.CM-09", "Detect", "Continuous Monitoring", "Computing hardware and software are monitored for unauthorized activity", "In Progress", "SOC Manager", "EDR rollout tracker", "2026-06-11"),
        ("RS.MA-01", "Respond", "Incident Management", "The incident response plan is executed once an incident is declared", "Not Started", "CISO", "IR plan v1 (untested)", "2026-02-15"),
        ("RS.CO-02", "Respond", "Incident Communication", "Internal and external stakeholders are notified of incidents", "Not Started", "CISO", "Communication plan draft", "2026-02-15"),
        ("RC.RP-01", "Recover", "Recovery Planning", "The recovery portion of the incident response plan is executed", "Not Started", "IT Ops Manager", "DR plan (last tested 2024)", "2026-01-10"),
        ("RC.CO-03", "Recover", "Recovery Communication", "Recovery activities are communicated to stakeholders", "Not Started", "COO", "n/a", "2026-01-10"),
    ]
    c.executemany('''INSERT INTO controls
        (id, function, category, description, status, owner, evidence, last_updated)
        VALUES (?,?,?,?,?,?,?,?)''', controls)

    vendors = [
        ("CloudHost Inc.", "Cloud infrastructure (IaaS)", "Customer data, PII", "Critical", "2025-11-01", "2026-11-01", "SOC 2 Type II clean; no findings"),
        ("PayGate Payments", "Payment processing", "Cardholder data (tokenized)", "Critical", "2025-09-15", "2026-09-15", "PCI-DSS AOC on file"),
        ("HelpDesk Pro", "Customer support platform", "Customer PII (limited)", "Medium", "2025-06-01", "2026-06-01", "Assessment overdue by 2 months"),
        ("MailFlow", "Email marketing", "Customer email addresses", "Low", "2025-08-20", "2026-08-20", "No material findings"),
        ("DataWarehouse Analytics", "Data analytics / BI", "Aggregated customer data, PII", "High", "2025-05-10", "2026-05-10", "Missing evidence of encryption at rest; remediation requested"),
    ]
    c.executemany('''INSERT INTO vendors
        (name, service, data_access, risk_tier, last_assessment, next_assessment, findings)
        VALUES (?,?,?,?,?,?,?)''', vendors)

    findings = [
        ("MFA not enforced on all privileged administrative accounts", "Internal Audit", "High", "PR.AA-01", "Enforce MFA org-wide for privileged roles via IAM policy update", "IAM Lead", "2026-09-01", "In Progress"),
        ("Incident response plan has not been tested in the last 12 months", "External Audit (SOC 2)", "Medium", "RS.MA-01", "Conduct tabletop exercise and document lessons learned", "CISO", "2026-09-30", "Open"),
        ("Disaster recovery plan last tested over 18 months ago", "Internal Audit", "High", "RC.RP-01", "Schedule and execute full DR failover test", "IT Ops Manager", "2026-10-15", "Open"),
        ("Vendor risk assessment overdue for HelpDesk Pro", "Internal Audit", "Medium", "GV.SC-01", "Complete overdue vendor assessment questionnaire", "Vendor Risk Manager", "2026-08-30", "Open"),
        ("Software asset inventory incomplete for SaaS applications", "Internal Audit", "Low", "ID.AM-02", "Deploy SaaS discovery tool and reconcile inventory", "IT Ops Manager", "2026-09-15", "In Progress"),
    ]
    c.executemany('''INSERT INTO audit_findings
        (description, source, severity, control_ref, remediation_plan, owner, due_date, status)
        VALUES (?,?,?,?,?,?,?,?)''', findings)

    policies = [
        ("Information Security Policy", "Security", "3.1", "CISO", "2025-08-01", "2026-08-01", "Approved"),
        ("Acceptable Use Policy", "Security", "2.0", "CISO", "2025-06-15", "2026-06-15", "Approved"),
        ("Incident Response Plan", "Security", "1.4", "CISO", "2025-02-15", "2026-02-15", "Approved"),
        ("Data Classification & Handling Policy", "Privacy", "1.2", "DPO", "2025-05-01", "2026-05-01", "Approved"),
        ("Vendor Risk Management Policy", "Third-Party", "1.0", "Vendor Risk Manager", "2025-01-10", "2026-01-10", "Approved"),
        ("Business Continuity / DR Plan", "Operations", "2.1", "COO", "2024-12-01", "2025-12-01", "Under Review"),
    ]
    c.executemany('''INSERT INTO policies
        (name, category, version, owner, last_review, next_review, status)
        VALUES (?,?,?,?,?,?,?)''', policies)

    conn.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def risk_score(likelihood, impact):
    if likelihood is None or impact is None:
        return 0
    return int(likelihood) * int(impact)


def risk_band(score):
    if score >= 16:
        return ("Critical", "band-critical")
    if score >= 10:
        return ("High", "band-high")
    if score >= 5:
        return ("Medium", "band-medium")
    return ("Low", "band-low")


def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


app.jinja_env.globals.update(risk_score=risk_score, risk_band=risk_band)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    conn = get_db()
    risks = conn.execute('SELECT * FROM risks').fetchall()
    controls = conn.execute('SELECT * FROM controls').fetchall()
    vendors = conn.execute('SELECT * FROM vendors').fetchall()
    findings = conn.execute('SELECT * FROM audit_findings').fetchall()
    policies = conn.execute('SELECT * FROM policies').fetchall()
    conn.close()

    # risk heat matrix: 5x5 grid, key=(likelihood, impact) -> count
    matrix = {}
    for r in risks:
        key = (r['likelihood'], r['impact'])
        matrix[key] = matrix.get(key, 0) + 1

    band_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in risks:
        band, _ = risk_band(risk_score(r['likelihood'], r['impact']))
        band_counts[band] += 1

    control_status_counts = {}
    for c in controls:
        control_status_counts[c['status']] = control_status_counts.get(c['status'], 0) + 1
    total_controls = len(controls) or 1
    implemented = control_status_counts.get('Implemented', 0)
    control_implementation_pct = round(100 * implemented / total_controls)

    open_findings = [f for f in findings if f['status'] != 'Closed']
    high_sev_open = [f for f in open_findings if f['severity'] in ('High', 'Critical')]

    overdue_policies = [p for p in policies if parse_date(p['next_review']) and parse_date(p['next_review']) < TODAY]
    overdue_vendors = [v for v in vendors if parse_date(v['next_assessment']) and parse_date(v['next_assessment']) < TODAY]

    return render_template('dashboard.html',
                            risks=risks,
                            matrix=matrix,
                            band_counts=band_counts,
                            control_status_counts=control_status_counts,
                            control_implementation_pct=control_implementation_pct,
                            total_controls=len(controls),
                            open_findings=open_findings,
                            high_sev_open=high_sev_open,
                            overdue_policies=overdue_policies,
                            overdue_vendors=overdue_vendors,
                            vendors=vendors,
                            today=TODAY)


# ---------------------------------------------------------------------------
# Risk Register
# ---------------------------------------------------------------------------

@app.route('/risks')
def risks_list():
    conn = get_db()
    risks = conn.execute('SELECT * FROM risks ORDER BY (likelihood*impact) DESC').fetchall()
    conn.close()
    return render_template('risks.html', risks=risks)


@app.route('/risks/add', methods=['POST'])
def risks_add():
    f = request.form
    conn = get_db()
    conn.execute('''INSERT INTO risks
        (title, category, description, likelihood, impact, owner, status, date_identified,
         mitigating_controls, residual_likelihood, residual_impact)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (f['title'], f['category'], f['description'], f['likelihood'], f['impact'],
         f['owner'], f['status'], f['date_identified'], f['mitigating_controls'],
         f.get('residual_likelihood') or None, f.get('residual_impact') or None))
    conn.commit()
    conn.close()
    flash('Risk added.', 'success')
    return redirect(url_for('risks_list'))


@app.route('/risks/<int:risk_id>/edit', methods=['POST'])
def risks_edit(risk_id):
    f = request.form
    conn = get_db()
    conn.execute('''UPDATE risks SET title=?, category=?, description=?, likelihood=?, impact=?,
        owner=?, status=?, date_identified=?, mitigating_controls=?, residual_likelihood=?, residual_impact=?
        WHERE id=?''',
        (f['title'], f['category'], f['description'], f['likelihood'], f['impact'],
         f['owner'], f['status'], f['date_identified'], f['mitigating_controls'],
         f.get('residual_likelihood') or None, f.get('residual_impact') or None, risk_id))
    conn.commit()
    conn.close()
    flash('Risk updated.', 'success')
    return redirect(url_for('risks_list'))


@app.route('/risks/<int:risk_id>/delete', methods=['POST'])
def risks_delete(risk_id):
    conn = get_db()
    conn.execute('DELETE FROM risks WHERE id=?', (risk_id,))
    conn.commit()
    conn.close()
    flash('Risk deleted.', 'info')
    return redirect(url_for('risks_list'))


@app.route('/export/risks.csv')
def export_risks():
    conn = get_db()
    risks = conn.execute('SELECT * FROM risks').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Category', 'Description', 'Likelihood', 'Impact',
                      'Inherent Score', 'Band', 'Owner', 'Status', 'Date Identified', 'Mitigating Controls'])
    for r in risks:
        score = risk_score(r['likelihood'], r['impact'])
        band, _ = risk_band(score)
        writer.writerow([r['id'], r['title'], r['category'], r['description'], r['likelihood'],
                          r['impact'], score, band, r['owner'], r['status'], r['date_identified'],
                          r['mitigating_controls']])
    return Response(output.getvalue(), mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment;filename=risk_register.csv'})


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

@app.route('/controls')
def controls_list():
    conn = get_db()
    controls = conn.execute('SELECT * FROM controls ORDER BY id').fetchall()
    conn.close()
    functions = sorted(set(c['function'] for c in controls))
    return render_template('controls.html', controls=controls, functions=functions)


@app.route('/controls/<control_id>/update', methods=['POST'])
def controls_update(control_id):
    f = request.form
    conn = get_db()
    conn.execute('''UPDATE controls SET status=?, owner=?, evidence=?, last_updated=? WHERE id=?''',
                 (f['status'], f['owner'], f['evidence'], datetime.today().strftime('%Y-%m-%d'), control_id))
    conn.commit()
    conn.close()
    flash('Control updated.', 'success')
    return redirect(url_for('controls_list'))


@app.route('/export/controls.csv')
def export_controls():
    conn = get_db()
    controls = conn.execute('SELECT * FROM controls').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Function', 'Category', 'Description', 'Status', 'Owner', 'Evidence', 'Last Updated'])
    for c in controls:
        writer.writerow([c['id'], c['function'], c['category'], c['description'], c['status'],
                          c['owner'], c['evidence'], c['last_updated']])
    return Response(output.getvalue(), mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment;filename=control_mapping.csv'})


# ---------------------------------------------------------------------------
# Vendors
# ---------------------------------------------------------------------------

@app.route('/vendors')
def vendors_list():
    conn = get_db()
    vendors = conn.execute('SELECT * FROM vendors ORDER BY risk_tier').fetchall()
    conn.close()
    return render_template('vendors.html', vendors=vendors, today=TODAY, parse_date=parse_date)


@app.route('/vendors/add', methods=['POST'])
def vendors_add():
    f = request.form
    conn = get_db()
    conn.execute('''INSERT INTO vendors (name, service, data_access, risk_tier, last_assessment, next_assessment, findings)
        VALUES (?,?,?,?,?,?,?)''',
        (f['name'], f['service'], f['data_access'], f['risk_tier'], f['last_assessment'], f['next_assessment'], f['findings']))
    conn.commit()
    conn.close()
    flash('Vendor added.', 'success')
    return redirect(url_for('vendors_list'))


@app.route('/vendors/<int:vendor_id>/delete', methods=['POST'])
def vendors_delete(vendor_id):
    conn = get_db()
    conn.execute('DELETE FROM vendors WHERE id=?', (vendor_id,))
    conn.commit()
    conn.close()
    flash('Vendor removed.', 'info')
    return redirect(url_for('vendors_list'))


# ---------------------------------------------------------------------------
# Audit Findings
# ---------------------------------------------------------------------------

@app.route('/audits')
def audits_list():
    conn = get_db()
    findings = conn.execute('SELECT * FROM audit_findings ORDER BY due_date').fetchall()
    conn.close()
    return render_template('audits.html', findings=findings, today=TODAY, parse_date=parse_date)


@app.route('/audits/add', methods=['POST'])
def audits_add():
    f = request.form
    conn = get_db()
    conn.execute('''INSERT INTO audit_findings
        (description, source, severity, control_ref, remediation_plan, owner, due_date, status)
        VALUES (?,?,?,?,?,?,?,?)''',
        (f['description'], f['source'], f['severity'], f['control_ref'], f['remediation_plan'],
         f['owner'], f['due_date'], f['status']))
    conn.commit()
    conn.close()
    flash('Finding added.', 'success')
    return redirect(url_for('audits_list'))


@app.route('/audits/<int:finding_id>/update', methods=['POST'])
def audits_update(finding_id):
    f = request.form
    conn = get_db()
    conn.execute('UPDATE audit_findings SET status=? WHERE id=?', (f['status'], finding_id))
    conn.commit()
    conn.close()
    flash('Finding updated.', 'success')
    return redirect(url_for('audits_list'))


@app.route('/audits/<int:finding_id>/delete', methods=['POST'])
def audits_delete(finding_id):
    conn = get_db()
    conn.execute('DELETE FROM audit_findings WHERE id=?', (finding_id,))
    conn.commit()
    conn.close()
    flash('Finding deleted.', 'info')
    return redirect(url_for('audits_list'))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.route('/policies')
def policies_list():
    conn = get_db()
    policies = conn.execute('SELECT * FROM policies ORDER BY next_review').fetchall()
    conn.close()
    return render_template('policies.html', policies=policies, today=TODAY, parse_date=parse_date)


@app.route('/policies/add', methods=['POST'])
def policies_add():
    f = request.form
    conn = get_db()
    conn.execute('''INSERT INTO policies (name, category, version, owner, last_review, next_review, status)
        VALUES (?,?,?,?,?,?,?)''',
        (f['name'], f['category'], f['version'], f['owner'], f['last_review'], f['next_review'], f['status']))
    conn.commit()
    conn.close()
    flash('Policy added.', 'success')
    return redirect(url_for('policies_list'))


@app.route('/policies/<int:policy_id>/delete', methods=['POST'])
def policies_delete(policy_id):
    conn = get_db()
    conn.execute('DELETE FROM policies WHERE id=?', (policy_id,))
    conn.commit()
    conn.close()
    flash('Policy deleted.', 'info')
    return redirect(url_for('policies_list'))


init_db()
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5050)
