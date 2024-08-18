async fn add_firewall_source_nat_rule(rule: SourceNatRule) -> HashSet<String> {
    let opnsense = CONFIG.lock().unwrap();
    if let Some(opnsense) = opnsense.as_ref() {
        
        let payload = json!({
            "rule": {                
                "enabled": "1",
                "interface": opnsense.wan_interface, //InterfaceField
                "protocol": rule.protocol,
                "destination_net": "wanip", //NetworkAliasField
                "destination_port": rule.destination_port, //PortField
                "target": opnsense.local_ip_address, //NetworkAliasField
                "target_port": rule.target_port, //PortField
                "description": format!("{}:{}", rule.container_id, rule.rule_number) //DescriptionField
            }
        });

        let response = opnsense.post_api_call("api/firewall/source_nat/addRule", payload).await;

        HashSet::new();
    } else {
        Err("OPNSense not initialized".into())
    }
}

/*
interface[]	"wan"
ipprotocol	"inet"
protocol	"udp"
src	"any"
srcbeginport	"any"
srcendport	"any"
dst	"wanip"
dstbeginport	"55555"
dstendport	"55555"
target	"192.168.1.10"
local-port	"55555"
poolopts	""
descr	"containerid:0"
tag	""
tagged	""
natreflection	"default"
associated-rule-id	"add-associated"
*/