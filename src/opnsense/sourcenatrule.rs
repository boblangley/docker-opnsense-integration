#[derive(Debug, Deserialize)]
struct SourceNatRule {
    rule_number: u64,
    container_id: String,
    protocol: String,
    destination_port: String,
    target_port: String
}