use log::{info, error};
use reqwest::{Client, Url};
use serde::Deserialize;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use native_tls::{TlsConnector, Certificate};

use opnsense::OPNSense;

pub mod docker;

#[tokio::main]
async fn main() {
    env_logger::init();

    let opnsense_hostname = env::var("OPNSENSE_HOSTNAME").expect("OPNSense API hostname must be set");
    let opnsense_api_key = env::var("OPNSENSE_API_KEY").expect("OPNSense API key must be set");
    let opnsense_api_secret = env::var("OPNSENSE_API_SECRET").expect("OPNSense API secret must be set");
    let opnsense_wan_interface = env::var("OPNSENSE_WAN_INTERFACE").expect("WAN_INTERFACE must be set");
    let local_ip_address = env::var("LOCAL_IP_ADDRESS").expect("LOCAL_IP_ADDRESS must be set");
    let container_polling_interval: u64 = env::var("CONTAINER_POLLING_INTERVAL")
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .expect("CONTAINER_POLLING_INTERVAL must be a valid integer");
    let cert_path = env::var("CERT_PATH").expect("CERT_PATH must be set");
    let key_path = env::var("KEY_PATH").expect("KEY_PATH must be set");

    // Load certificates
    let certs = load_certs(cert_path).expect("Failed to load certificates");
    let tls_connector = TlsConnector::builder().add_root_certificate(certs).build().expect("Failed to create TLS connector");
    let client = Client::builder().use_tls(tls_connector).build().expect("Failed to build HTTP client");

    // Health check reporting
    info!("Service started. Reporting live...");
    info!("Health check: live");

    OPNSense::initialize(
        client,
        opnsense_hostname,
        opnsense_api_key,
        opnsense_api_secret,
        opnsense_wan_interface,
        local_ip_address
    );

    let mut rule_description_collection = opnsense::search_firewall_source_nat_rules().await;
    let mut hostname_collection = opnsense::search_existing_unbound_host_overrides().await;

    info!("Health check: ready");

    // Create the signals handler
    let signals = Signals::new(&[SIGTERM, SIGINT, SIGQUIT]).unwrap();

    loop {
        tokio::select! {
            _ = handle_signals(signals.clone()) => {
                info!("Shutting down...");
                break;
            },
            _ = run_main_loop(
                &client, 
                &api_ip, 
                &api_key, 
                &api_secret, 
                &local_ip_address, 
                &wan_interface, 
                &mut rule_description_collection, 
                &mut hostname_collection
            ) => {},
        }
        sleep(Duration::from_secs(container_polling_interval)).await;
    }
}

fn load_certs(cert_path: String) -> Result<Certificate, native_tls::Error> {
    let file = File::open(Path::new(&cert_path))?;
    let mut reader = BufReader::new(file);
    let cert = Certificate::from_pem(&mut reader)?;
    Ok(cert)
}

async fn get_existing_port_forward_descriptions(
    client: &Client,
    api_ip: &str,
    api_key: &str,
    api_secret: &str,
    wan_interface: &str,
) -> HashSet<String> {
    // Mock implementation. Replace with API call to get existing port forward rules.
    // Parse response and return a collection of descriptions.
    HashSet::new()
}



async fn run_main_loop(
    client: &Client,
    api_ip: &str,
    api_key: &str,
    api_secret: &str,
    local_ip: &str,
    wan_interface: &str,
    rule_description_collection: &mut HashSet<String>,
    hostname_collection: &mut HashSet<String>,
) {        
    let containers = get_running_containers(client).await;

    for container in containers {
        if let Some(caddy_label) = container.Labels.get("caddy") {
            if caddy_label.ends_with(".local") {
                if !hostname_collection.contains(caddy_label) {
                    match create_dns_record(client, api_ip, api_key, api_secret, local_ip, caddy_label).await {
                        Ok(_) => {
                            hostname_collection.insert(caddy_label.clone());
                            info!("Added DNS record for {}", caddy_label);
                        }
                        Err(e) => error!("Failed to add DNS record for {}: {}", caddy_label, e),
                    }
                }
            }
        }

        // Handle port forwarding
        let port_forward_labels: Vec<(&String, &String)> = container.Labels.iter()
            .filter(|(key, _)| key.starts_with("port_forward."))
            .collect();

        if !port_forward_labels.is_empty() {
            handle_port_forwarding(
                client,
                api_ip,
                api_key,
                api_secret,
                local_ip,
                wan_interface,
                &container,
                rule_description_collection,
                port_forward_labels,
            ).await;
        }
    }
}



async fn create_dns_record(
    client: &Client,
    api_ip: &str,
    api_key: &str,
    api_secret: &str,
    local_ip: &str,
    hostname: &str,
) -> Result<(), reqwest::Error> {
    let url = format!("https://{}/api/dns/add", api_ip);
    let dns_record = serde_json::json!({
        "hostname": hostname,
        "ip": local_ip,
    });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}:{}", api_key, api_secret))
        .json(&dns_record)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn handle_port_forwarding(
    client: &Client,
    api_ip: &str,
    api_key: &str,
    api_secret: &str,
    local_ip: &str,
    wan_interface: &str,
    container: &Container,
    rule_description_collection: &mut HashSet<String>,
    port_forward_labels: Vec<(&String, &String)>,
) {
    let mut rules: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (label, value) in port_forward_labels {
        let parts: Vec<&str> = label.split('.').collect();
        if parts.len() != 3 {
            error!("Invalid label format: {} for container {}", label, container.Id);
            continue;
        }

        let rule_number = parts[1].to_string();
        let property = parts[2].to_string();

        if property == "description" || property == "interface" || property == "destination" {
            error!(
                "Unsupported label property {} for container {} ({})",
                label, container.Id, container.Names.join(", ")
            );
            continue;
        }

        rules.entry(rule_number.clone())
            .or_insert_with(HashMap::new)
            .insert(property, value.clone());
    }

    for (rule_number, rule) in rules.iter_mut() {
        rule.insert("description".to_string(), format!("{}:{}", container.Id, rule_number));
        rule.insert("interface".to_string(), wan_interface.to_string());
        rule.insert("destination".to_string(), local_ip.to_string());

        if rule_description_collection.contains(&rule["description"]) {
            continue;
        }

        match create_port_forward_rule(client, api_ip, api_key, api_secret, rule).await {
            Ok(_) => {
                rule_description_collection.insert(rule["description"].clone());
                info!(
                    "Added port forward rule for container {} ({})",
                    container.Id, container.Names.join(", ")
                );
            }
            Err(e) => error!(
                "Failed to add port forward rule for container {} ({}): {}",
                container.Id, container.Names.join(", "), e
            ),
        }
    }
}

async fn create_port_forward_rule(
    client: &Client,
    api_ip: &str,
    api_key: &str,
   
