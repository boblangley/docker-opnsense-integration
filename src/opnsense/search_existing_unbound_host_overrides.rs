async fn search_existing_unbound_host_overrides() -> HashSet<String> {
    let opnsense = CONFIG.lock().unwrap();
    if let Some(opnsense) = opnsense.as_ref() {
        
        let payload = json!({
            "current": 1,
            "rowCount": 100,
            "sort": {},
            "searchPhrase": ""
        });

        let response = opnsense.post_api_call("api/unbound/settings/searchHostOverride", payload).await;

        HashSet::new();
    } else {
        Err("OPNSense not initialized".into())
    }
}