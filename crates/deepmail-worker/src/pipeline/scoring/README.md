# Threat Scoring Engine

The Threat Scoring Engine orchestrates the finalized signals from the pipeline and computes a normalized 0.0 - 100.0 risk score.

## Risk Dimensions

The final score is composed of 4 equally-weighted dimensions (25% each):

1. **Identity**: Penalizes authentication failures (SPF/DKIM/DMARC) and sender masquerading (Reply-To mismatches).
2. **Infrastructure**: Penalizes emails routing through multiple suspicious hops, or possessing high IOC density.
3. **Content**: Evaluates URL structural risks and incorporates the `PhishingKeywordResult` for deceptive language.
4. **Attachment**: Assesses high entropy payloads, suspicious extensions, and MIME discrepancies.

## Confidence Interval

To provide context to the score, a `confidence` metric (0.0 - 1.0) is returned. This metric tracks how many elements of the email were actually available to analyze. Missing headers or lack of body text will lower the confidence, signaling to analysts that the score is based on incomplete data.

## Clamping

The engine strictly clamps final scores to a ceiling of 100.0, preventing mathematical overflow attacks where an email contains thousands of URLs merely to manipulate downstream alerting thresholds.
