"""Automated access-control tests mapped to SOC 2 and ISO/IEC 27001:2022.

Reads a user export and an HR roster, runs each control test, and writes
findings with severity, owner, and due date for remediation tracking.
"""
import csv
from datetime import date, datetime, timedelta
from pathlib import Path

DATA = Path(__file__).parent / "sample_data"
AS_OF = date(2026, 11, 16)
INACTIVE_DAYS = 90
SLA_DAYS = {"High": 7, "Medium": 30, "Low": 60}
OWNER = "IT Identity & Access"


def load(name):
    with open(DATA / name, newline="") as f:
        return list(csv.DictReader(f))


def finding(test_id, control, severity, user, detail):
    return {
        "test_id": test_id,
        "control": control,
        "severity": severity,
        "user": user,
        "detail": detail,
        "owner": OWNER,
        "due_date": (AS_OF + timedelta(days=SLA_DAYS[severity])).isoformat(),
        "status": "Open",
    }


def run():
    users = load("idp_users.csv")
    hr = {r["email"]: r for r in load("hr_roster.csv")}
    admins = {r["email"] for r in load("approved_admins.csv")}
    findings = []

    for u in users:
        if u["status"] != "ACTIVE":
            continue
        email = u["email"]

        # AC-01: terminated in HR but still active
        if hr.get(email, {}).get("employment_status") == "Terminated":
            findings.append(finding("AC-01", "SOC 2 CC6.2/CC6.3 | ISO A.5.18", "High", email,
                                    f"Terminated {hr[email]['termination_date']} but account still active"))

        # AC-02: no MFA
        if u["mfa_enrolled"].lower() != "true":
            findings.append(finding("AC-02", "SOC 2 CC6.1 | ISO A.8.5", "High", email,
                                    "Active account without MFA"))

        # AC-03: inactive 90+ days
        last = datetime.strptime(u["last_login"], "%Y-%m-%d").date()
        if (AS_OF - last).days >= INACTIVE_DAYS:
            findings.append(finding("AC-03", "SOC 2 CC6.2 | ISO A.5.18", "Medium", email,
                                    f"No login for {(AS_OF - last).days} days"))

        # AC-04: unapproved admin
        if u["is_admin"].lower() == "true" and email not in admins:
            findings.append(finding("AC-04", "SOC 2 CC6.3 | ISO A.8.2", "High", email,
                                    "Admin rights not on approved admin list"))

    out = Path(__file__).parent / "findings.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(findings[0].keys()) if findings else ["test_id"])
        w.writeheader()
        w.writerows(findings)

    tests = ["AC-01", "AC-02", "AC-03", "AC-04"]
    print(f"Control tests as of {AS_OF} | {len(users)} accounts reviewed")
    for t in tests:
        n = sum(1 for x in findings if x["test_id"] == t)
        print(f"  {t}: {'PASS' if n == 0 else f'FAIL ({n} finding(s))'}")
    print(f"Findings written to {out.name}")


if __name__ == "__main__":
    run()
