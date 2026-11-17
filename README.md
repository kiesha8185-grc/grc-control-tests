# GRC Control Tests

Lightweight, automated control tests that check **access-control evidence pulled directly from a system export** (for example, an identity provider user list joined to an HR roster) instead of collecting screenshots.

Built with AI coding tools as a proof of concept for continuous control validation.

## What it tests

| Test | What it checks | SOC 2 | ISO/IEC 27001:2022 |
|---|---|---|---|
| AC-01 Terminated access | Users terminated in HR are still active in the identity system | CC6.2, CC6.3 | A.5.18 |
| AC-02 MFA enforcement | Active users without multi-factor authentication | CC6.1 | A.8.5 |
| AC-03 Inactive accounts | Active accounts with no login in 90+ days | CC6.2 | A.5.18 |
| AC-04 Privileged access | Admin accounts not on the approved admin list | CC6.3 | A.8.2 |

## How it works
1. Reads the user export (`sample_data/idp_users.csv`) and the HR roster (`sample_data/hr_roster.csv`)
2. Runs each control test
3. Writes `findings.csv`: each failure with severity, a control owner, and a due date, ready to track to closure

## Run it
```bash
python control_tests.py
```
Uses only the Python standard library. Sample data is fictional.

## Why
Compliance platforms automate a lot, but not every control. Small custom tests like these extend continuous control validation, and each one is written to prove exactly what the control requires.
