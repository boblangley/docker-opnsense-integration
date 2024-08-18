pub async fn search_firewall_source_nat_rules() -> Result<HashSet<String>, Box<dyn Error>> {
    let opnsense = CONFIG.lock().unwrap();
    if let Some(opnsense) = opnsense.as_ref() {
        
        let payload = json!({
            "current": 1,
            "rowCount": 100,
            "sort": {},
            "searchPhrase": ""
        });

        let response = opnsense.post_api_call("api/firewall/source_nat/search", payload).await

        HashSet::new();
    } else {
        Err("OPNSense not initialized".into())
    }
}