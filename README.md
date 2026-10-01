# GRC Command Center

A self-contained Governance, Risk & Compliance management tool built with Python/Flask + SQLite.

## What it does

- **Dashboard** — KPIs, a Likelihood x Impact risk heat map, control implementation status, and a "needs attention" feed (overdue findings/policies/vendor reviews)
- **Risk Register** — add/edit/delete risks, auto-calculated inherent risk score (Likelihood x Impact) and residual risk after controls, CSV export
- **Control Mapping** — a starter set of controls mapped to **NIST CSF 2.0** functions (Govern, Identify, Protect, Detect, Respond, Recover), with status/owner/evidence tracking, CSV export
- **Vendor Risk** — third-party risk tiering with assessment due-date tracking and overdue flags
- **Audit Findings** — findings register with severity, remediation plans, owners, due dates, and status
- **Policies** — policy inventory with review cadence and overdue flags

It comes pre-loaded with realistic sample data (8 risks, 20 NIST CSF controls, 5 vendors, 5 audit findings, 6 policies) so it's immediately useful for a demo, portfolio project, or as a template for a real program.
