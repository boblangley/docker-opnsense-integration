use reqwest::Client;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use json::JsonValue;
use std::error::Error;

// Define a OPNSense struct to hold the API configuration
pub struct OPNSenseConfig {
    client: Client,
    hostname: String,
    api_key: String,
    api_secret: String,
    wan_interface: String,
    local_ip_address: String
}

pub struct OPNSenseAPI {
    config: OPNSenseConfig
}

pub struct UnboundHostOverridesAPI
{
    base_api: OPNSenseAPI
}


impl OPNSenseAPI {
    // Initialize the Config with the provided values
    pub fn initialize(&config: OPNSenseConfig) -> OPNSenseAPI
    {
        OPNSenseAPI
        {
            config
        };
    }

    // Private function to perform a POST API call
    async fn post_api_call(
        &self,
        path: &str,
        payload: &HashMap<&str, &str>,
    ) -> Result<JsonValue, Box<dyn Error>> {
        let url = format!("https://{}/{}", self.hostname, path.trim_start_matches('/'));
        
        let response = self.client
            .post(&url)
            .basic_auth(&self.api_key, Some(&self.api_secret))
            .json(payload)
            .send()
            .await?;

        if response.status().is_success() {
            let response_text = response.text().await?;
            let parsed_json = json::parse(&response_text)
                .expect("Failed to parse the response text as JSON");

            Ok(parsed_json)
        } else {
            Err(format!("Failed to send POST request: {}", response.status()).into())
        }
    }

    // Private function to perform a GET API call
    async fn get_api_call(
        &self,
        path: &str,
    ) -> Result<JsonValue, Box<dyn Error>> {
        let url = format!("https://{}/{}", self.hostname, path.trim_start_matches('/'));
        let response = self.client
            .get(&url)
            .basic_auth(&self.api_key, Some(&self.api_secret))
            .send()
            .await?;

        if response.status().is_success() {
            let response_text = response.text().await?;
            let parsed_json = json::parse(&response_text)
                .expect("Failed to parse the response text as JSON");

            Ok(parsed_json)
        } else {
            Err(format!("Failed to send GET request: {}", response.status()).into())
        }
    }    

    pub mod search_firewall_source_nat_rules;
    pub mod search_existing_unbound_host_overrides;
    pub mod add_firewall_source_nat_rule;
}



pub mod sourcenatrule;



pub mod hostoverride;
pub mod add_unbound_host_override;