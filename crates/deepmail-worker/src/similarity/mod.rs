//! Similarity Engine for detecting phishing campaigns and infrastructure reuse.

use deepmail_common::errors::DeepMailError;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Fingerprint of an email for similarity matching.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailFingerprint {
    pub subject_simhash: u64,
    pub body_simhash: u64,
    pub html_structure_hash: String,
}

/// Calculate a simple SimHash for text.
/// 
/// Note: In a full production env, we'd use a more robust implementation 
/// with tokenization and weightings. This is the core logical foundation.
pub fn calculate_simhash(text: &str) -> u64 {
    let mut v = [0i32; 64];
    
    for word in text.split_whitespace() {
        let mut h = DefaultHasher::new();
        word.hash(&mut h);
        let hash = h.finish();
        
        for i in 0..64 {
            let bit = (hash >> i) & 1;
            if bit == 1 {
                v[i] += 1;
            } else {
                v[i] -= 1;
            }
        }
    }
    
    let mut fingerprint = 0u64;
    for i in 0..64 {
        if v[i] > 0 {
            fingerprint |= 1 << i;
        }
    }
    
    fingerprint
}

/// Calculate a hash of the HTML structure by stripping content.
pub fn calculate_html_structure_hash(html: &str) -> String {
    let mut structure = String::new();
    let mut in_tag = false;
    
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
            structure.push('<');
        } else if c == '>' {
            in_tag = false;
            structure.push('>');
        } else if in_tag && c.is_whitespace() {
            // Stop at first space in tag to keep only the tag name
            in_tag = false;
        } else if in_tag {
            structure.push(c);
        }
    }
    
    let mut h = DefaultHasher::new();
    structure.hash(&mut h);
    format!("{:x}", h.finish())
}

/// Compare two SimHashes using Hamming distance.
pub fn compare_simhash(h1: u64, h2: u64) -> f64 {
    let distance = (h1 ^ h2).count_ones();
    1.0 - (distance as f64 / 64.0)
}
