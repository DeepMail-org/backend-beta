# Phishing Keywords Module

This module performs heuristic content scanning against the email bodies, targeting language patterns typically used in social engineering and phishing attacks.

## Mechanism

- Scans body text and HTML sequentially.
- Uses a weighted dictionary of over 40 distinct phishing phrases (e.g. `urgent action required`, `verify your account`, `unusual sign-in activity`).
- Generates a cumulative score contribution, adding up to 30 points to the overall "Content" threat score index.

## Rationale

Attackers often use urgency and authority to elicit action before a victim can logically verify the source. Standard indicator matching fails if the URL is novel, but deceptive language is persistent across campaigns.
