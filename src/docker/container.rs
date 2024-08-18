#[derive(Debug, Deserialize)]
struct Container {
    Id: String,
    Names: Vec<String>,
    Labels: HashMap<String, String>,
}