async fn add_unbound_host_override(host: String, description: String) -> HashSet<String> {
    let opnsense = CONFIG.lock().unwrap();
    if let Some(opnsense) = opnsense.as_ref() {
        
        let payload = json!({
            "host": {
                "enabled": "1",
                "hostname": host,
                "domain": local,
                "rr": "A",
                "mxprio": "",
                "mx": "",
                "server": opnsense.local_ip_address,
                "description": description
            }
        });

        let response = opnsense.post_api_call("api/firewall/source_nat/addRule", payload).await;

        HashSet::new();
    } else {
        Err("OPNSense not initialized".into())
    }
}