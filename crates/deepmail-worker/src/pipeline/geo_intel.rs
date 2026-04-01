use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use maxminddb::{geoip2, Reader};
use serde::{Deserialize, Serialize};

use deepmail_common::cache::ThreatCache;
use deepmail_common::config::IntelConfig;
use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIntel {
    pub ip: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub abuse_confidence: Option<u8>,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub is_hosting: bool,
    pub confidence_score: f64,
    pub source: String,
    pub provider_version: Option<String>,
    pub resolved_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIpDbData {
    abuse_confidence_score: Option<u8>,
    isp: Option<String>,
    is_tor: Option<bool>,
    usage_type: Option<String>,
}

fn is_public_ipv4(ip: &str) -> Option<Ipv4Addr> {
    let parsed = ip.parse::<Ipv4Addr>().ok()?;
    if parsed.is_private()
        || parsed.is_loopback()
        || parsed.is_link_local()
        || parsed.is_multicast()
        || parsed.is_broadcast()
        || parsed.is_documentation()
        || parsed.is_unspecified()
    {
        return None;
    }
    Some(parsed)
}

fn parse_utc_ts(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|ts| ts.with_timezone(&Utc))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn compute_confidence(
    has_city: bool,
    has_asn: bool,
    abuse_confidence: Option<u8>,
    is_tor: bool,
    is_proxy: bool,
) -> f64 {
    let mut score = 0.55;
    if has_city {
        score += 0.2;
    }
    if has_asn {
        score += 0.15;
    }
    if let Some(abuse) = abuse_confidence {
        score += (abuse as f64 / 100.0) * 0.1;
    }
    if is_tor || is_proxy {
        score += 0.05;
    }
    score.clamp(0.0, 1.0)
}

fn load_geo_from_mmdb(config: &IntelConfig, ip: Ipv4Addr) -> Result<Option<GeoIntel>> {
    let city_reader = match Reader::open_readfile(&config.geoip_mmdb_city_path) {
        Ok(reader) => reader,
        Err(err) => {
            tracing::warn!(
                path = %config.geoip_mmdb_city_path,
                error = %err,
                "GeoLite2 city DB not available"
            );
            return Ok(None);
        }
    };

    let asn_reader = match Reader::open_readfile(&config.geoip_mmdb_asn_path) {
        Ok(reader) => Some(reader),
        Err(err) => {
            tracing::warn!(
                path = %config.geoip_mmdb_asn_path,
                error = %err,
                "GeoLite2 ASN DB not available"
            );
            None
        }
    };

    let city: geoip2::City = match city_reader.lookup(IpAddr::V4(ip)) {
        Ok(data) => data,
        Err(err) => {
            tracing::debug!(ip = %ip, error = %err, "GeoLite2 lookup miss");
            return Ok(None);
        }
    };

    let lat = city
        .location
        .as_ref()
        .and_then(|l| l.latitude)
        .unwrap_or(0.0);
    let lon = city
        .location
        .as_ref()
        .and_then(|l| l.longitude)
        .unwrap_or(0.0);
    if lat.abs() < f64::EPSILON && lon.abs() < f64::EPSILON {
        return Ok(None);
    }

    let country = city
        .country
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|names| names.get("en"))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let city_name = city
        .city
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|names| names.get("en"))
        .map(|v| v.to_string());

    let region = city
        .subdivisions
        .as_ref()
        .and_then(|subs| subs.first())
        .and_then(|s| s.names.as_ref())
        .and_then(|names| names.get("en"))
        .map(|v| v.to_string());

    let (asn, org) = if let Some(reader) = asn_reader {
        match reader.lookup::<geoip2::Asn<'_>>(IpAddr::V4(ip)) {
            Ok(asn_data) => (
                asn_data.autonomous_system_number,
                asn_data
                    .autonomous_system_organization
                    .map(|v| v.to_string()),
            ),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    let now = Utc::now();
    Ok(Some(GeoIntel {
        ip: ip.to_string(),
        lat,
        lon,
        country,
        city: city_name,
        region,
        asn,
        org,
        abuse_confidence: None,
        is_tor: false,
        is_proxy: false,
        is_hosting: false,
        confidence_score: compute_confidence(true, asn.is_some(), None, false, false),
        source: "maxmind_geolite2".to_string(),
        provider_version: Some("geolite2".to_string()),
        resolved_at: now.to_rfc3339(),
        expires_at: (now + Duration::seconds(config.geoip_ttl_secs as i64)).to_rfc3339(),
    }))
}

async fn enrich_with_abuseipdb(config: &IntelConfig, intel: &mut GeoIntel) {
    if !config.enable_abuse_provider {
        return;
    }

    let api_key = match std::env::var(&config.abuse_provider_api_key_env) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return,
    };

    let url = format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90&verbose",
        intel.ip
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let response = match client
        .get(url)
        .header("Accept", "application/json")
        .header("Key", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    if !response.status().is_success() {
        return;
    }

    let payload = match response.json::<AbuseIpDbResponse>().await {
        Ok(p) => p,
        Err(_) => return,
    };

    intel.abuse_confidence = payload.data.abuse_confidence_score;
    if intel.org.is_none() {
        intel.org = payload.data.isp;
    }
    intel.is_tor = payload.data.is_tor.unwrap_or(false);

    if let Some(usage) = payload.data.usage_type {
        let usage_lower = usage.to_lowercase();
        intel.is_hosting = usage_lower.contains("hosting") || usage_lower.contains("datacenter");
        intel.is_proxy = usage_lower.contains("proxy") || usage_lower.contains("vpn");
    }

    intel.confidence_score = compute_confidence(
        intel.city.is_some(),
        intel.asn.is_some(),
        intel.abuse_confidence,
        intel.is_tor,
        intel.is_proxy,
    );
    intel.provider_version = Some("geolite2+abuseipdb".to_string());
}

fn load_ip_geo_intel_from_db(pool: &DbPool, ip: &str) -> Result<Option<GeoIntel>, DeepMailError> {
    let conn = pool.get()?;
    let row = conn
        .query_row(
            "SELECT ip, lat, lon, country, city, region, asn, org,
                    abuse_confidence, is_tor, is_proxy, is_hosting,
                    confidence_score, source, provider_version, last_resolved_at, expires_at
             FROM ip_geo_intel WHERE ip = ?1",
            rusqlite::params![ip],
            |r| {
                Ok(GeoIntel {
                    ip: r.get(0)?,
                    lat: r.get(1)?,
                    lon: r.get(2)?,
                    country: r.get(3)?,
                    city: r.get(4)?,
                    region: r.get(5)?,
                    asn: r.get(6)?,
                    org: r.get(7)?,
                    abuse_confidence: r.get(8)?,
                    is_tor: r.get::<_, i64>(9)? == 1,
                    is_proxy: r.get::<_, i64>(10)? == 1,
                    is_hosting: r.get::<_, i64>(11)? == 1,
                    confidence_score: r.get(12)?,
                    source: r.get(13)?,
                    provider_version: r.get(14)?,
                    resolved_at: r.get(15)?,
                    expires_at: r.get(16)?,
                })
            },
        )
        .ok();

    Ok(row)
}

fn persist_ip_geo_intel(pool: &DbPool, intel: &GeoIntel) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO ip_geo_intel (
            ip, lat, lon, country, city, region, asn, org,
            abuse_confidence, is_tor, is_proxy, is_hosting,
            confidence_score, source, provider_version, first_seen_at,
            last_resolved_at, expires_at
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
            ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, datetime('now'),
            ?16, ?17
         )
         ON CONFLICT(ip) DO UPDATE SET
            lat = excluded.lat,
            lon = excluded.lon,
            country = excluded.country,
            city = excluded.city,
            region = excluded.region,
            asn = excluded.asn,
            org = excluded.org,
            abuse_confidence = excluded.abuse_confidence,
            is_tor = excluded.is_tor,
            is_proxy = excluded.is_proxy,
            is_hosting = excluded.is_hosting,
            confidence_score = excluded.confidence_score,
            source = excluded.source,
            provider_version = excluded.provider_version,
            last_resolved_at = excluded.last_resolved_at,
            expires_at = excluded.expires_at",
        rusqlite::params![
            intel.ip,
            intel.lat,
            intel.lon,
            intel.country,
            intel.city,
            intel.region,
            intel.asn,
            intel.org,
            intel.abuse_confidence,
            if intel.is_tor { 1 } else { 0 },
            if intel.is_proxy { 1 } else { 0 },
            if intel.is_hosting { 1 } else { 0 },
            intel.confidence_score,
            intel.source,
            intel.provider_version,
            intel.resolved_at,
            intel.expires_at,
        ],
    )?;
    Ok(())
}

pub async fn resolve_ip_intel(
    cache: &ThreatCache,
    pool: &DbPool,
    config: &IntelConfig,
    ip: &str,
) -> Result<Option<GeoIntel>> {
    let ipv4 = match is_public_ipv4(ip) {
        Some(ipv4) => ipv4,
        None => return Ok(None),
    };

    if let Ok(Some(cached)) = cache.get_ip_lookup::<GeoIntel>(ip).await {
        if parse_utc_ts(&cached.expires_at)
            .map(|expires| expires > Utc::now())
            .unwrap_or(true)
        {
            return Ok(Some(cached));
        }
    }

    if let Some(row) = load_ip_geo_intel_from_db(pool, ip)? {
        if parse_utc_ts(&row.expires_at)
            .map(|expires| expires > Utc::now())
            .unwrap_or(false)
        {
            let _ = cache
                .set_with_ttl("ip", ip, &row, config.geoip_ttl_secs)
                .await;
            return Ok(Some(row));
        }
    }

    let mut intel = match load_geo_from_mmdb(config, ipv4)? {
        Some(intel) => intel,
        None => return Ok(None),
    };

    enrich_with_abuseipdb(config, &mut intel).await;
    intel.resolved_at = now_iso();
    intel.expires_at = (Utc::now() + Duration::seconds(config.geoip_ttl_secs as i64)).to_rfc3339();

    persist_ip_geo_intel(pool, &intel)?;
    let _ = cache
        .set_with_ttl("ip", ip, &intel, config.geoip_ttl_secs)
        .await;

    Ok(Some(intel))
}
