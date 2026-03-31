//! GeoIP lookup provider for real-time geolocation mapping.
//!
//! Uses the ip-api.com JSON API to fetch latitude, longitude, and country
//! for a given public IPv4 address. Results are intended to be stored
//! in IOC metadata for frontend visualization.

use serde::{Deserialize, Serialize};
use anyhow::Result;

/// Geolocation data returned by the GeoIP provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpData {
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub query: String, // The IP address
}

/// Response format for ip-api.com
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    lat: Option<f64>,
    lon: Option<f64>,
    country: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    query: String,
    message: Option<String>,
}

/// Lookup geolocation data for a public IP address.
///
/// # Arguments
/// * `ip` - A valid public IPv4 address string.
///
/// # Returns
/// * `Ok(GeoIpData)` if the lookup was successful.
/// * `Err` if the API call failed or returned an error status.
pub async fn lookup_geoip(ip: &str) -> Result<GeoIpData> {
    let url = format!("http://ip-api.com/json/{}?fields=status,message,country,city,lat,lon,isp,query", ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let response = client.get(url).send().await?;
    let api_res: IpApiResponse = response.json().await?;

    if api_res.status != "success" {
        let msg = api_res.message.unwrap_or_else(|| "Unknown API error".to_string());
        return Err(anyhow::anyhow!("GeoIP lookup failed for {}: {}", ip, msg));
    }

    Ok(GeoIpData {
        lat: api_res.lat.unwrap_or(0.0),
        lon: api_res.lon.unwrap_or(0.0),
        country: api_res.country.unwrap_or_else(|| "Unknown".to_string()),
        city: api_res.city,
        isp: api_res.isp,
        query: api_res.query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Skip in CI/restricted envs if no network
    async fn test_lookup_google_dns() {
        let res = lookup_geoip("8.8.8.8").await.unwrap();
        assert_eq!(res.query, "8.8.8.8");
        assert!(res.lat != 0.0);
    }
}
