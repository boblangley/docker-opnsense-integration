#[derive(Debug, Deserialize)]
struct SourceNatRule {
    rule_number: u64,
    container_id: String,
    protocol: String,
    destination_port: String,
    target_port: String
}

pub struct FirewallSourceNatRulesAPI
{
    base_api: OPNSenseAPI
}

impl FirewallSourceNatRulesAPI {
    pub fn get_firewall_source_nat_rules() -> Result<HashSet<String>, Box<dyn Error>> {
                
        
        if let base_api = self.base_api opnsense.as_ref() {
            
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

    pub fn add_firewall_source_nat_rule(&rule: SourceNatRule)
    {
        //self.base_api
    }
}