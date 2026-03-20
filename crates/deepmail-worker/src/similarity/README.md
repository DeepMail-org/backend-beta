# Similarity Engine

The Similarity Engine detects phishing campaigns and malware reuse by comparing
newly analyzed emails against historical data using fuzzy hashing and structural
fingerprinting.

## Hashing Strategies

1. **SimHash (NLP-based)**: Used for subject and email body text. It maps high-dimensional
   text data into a bitstring where similar texts have a small Hamming distance.
2. **HTML Structure Hashing**: Strips all content and attributes, leaving only the
   raw DOM tag sequence. This detects "kits" used by the same attacker.
3. **URL Pattern Similarity**: Normalizes URLs and compares path/query patterns to
   detect automated generation.
4. **TLSH (Trend Micro Locality Sensitive Hash)**: Used for attachment fuzzy matching.

## Performance Considerations

- **Time Windowing**: Only compares against emails from the last 30 days to limit DB load.
- **Hamming Distance**: Bitwise comparison is extremely fast for SimHash.

## Security Considerations

- **Input Sanitization**: All text is sanitized and normalized before hashing.
- **Memory Safety**: Rust's ownership model prevents buffer overflows during large body parsing.
