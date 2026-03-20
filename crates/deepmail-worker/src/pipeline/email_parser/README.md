# Email Parser Module

This module is responsible for the foundational extraction of components from raw RFC 5322 (`.eml`) formats. It powers the start of the DeepMail analysis pipeline.

## Core Responsibilities

1. **Header Extraction**: Parses standard email headers like `From`, `To`, `Date`, `Subject`, `Message-ID`, and specifically the routing `Received` chains.
2. **Body Decoding**: Extracts plaintext and HTML body components, handling Quoted-Printable and Base64 encodings automatically.
3. **Attachment Structuring**: Reconstructs attachments from multipart MIME boundaries, extracts filenames, and provides raw bytes for downstream analysis.

## Security & Reliability

- The parser uses `mailparse` which is highly resilient against malformed `.eml` inputs, ensuring the pipeline doesn't crash on attacker-crafted syntax errors.
- Extracting raw body text without execution allows downstream modules (like Phishing Keywords and IOC Extractor) to analyze content safely.
