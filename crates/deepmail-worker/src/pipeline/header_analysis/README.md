# Header Analysis Module

This module inspects email metadata to uncover routing anomalies and identity spoofing, forming the "Identity" dimension of the threat score.

## Core Responsibilities

1. **Authentication Verification**: Parses Authentication-Results headers to extract SPF, DKIM, and DMARC signals, categorising them as pass/fail/neutral/error.
2. **Received Chain Tracing**: Maps the hop-by-hop traversal of the email. Identifies the originating client IP to detect open relays or botnet infrastructure.
3. **Identity Spoofing Checks**: Compares `From` against `Reply-To` and `Return-Path` to find Reply-To mismatch attacks frequently used in BEC (Business Email Compromise).

## Threat Output

- A failing DMARC or DKIM/SPF mismatch heavily penalises the identity score.
- Mismatched Return paths highlight infrastructure masquerading.
