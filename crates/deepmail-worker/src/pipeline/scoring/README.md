# Threat Scoring Engine

The Scoring Engine provides a multi-dimensional threat assessment of analyzed
emails. Instead of a single linear score, it categorizes risk into four distinct
pillars.

## Scoring Categories

1. **Identity Risk (30%)**: SPF/DKIM/DMARC results and sender spoofing detection.
2. **Infrastructure Risk (25%)**: IP reputation, domain age, and ASN hosting risk.
3. **Content Risk (25%)**: Phishing keywords, urgency patterns, and structural anomalies.
4. **Attachment Risk (20%)**: Executables, macros, and entropy-based obfuscation.

## Score Interpretation

- **0–30 (Safe)**: Minimal anomalies detected.
- **30–60 (Suspicious)**: Requires manual review or sandbox detonation.
- **60–90 (Malicious)**: High-fidelity indicators of compromise.
- **90+ (Critical)**: Verified threat (e.g., active C2 or known malware hash).

## Confidence Score

Confidence is calculated based on the number and diversity of signals triggered.
A single high-impact signal (like a malware match) yields higher confidence than
many low-impact heuristics.
