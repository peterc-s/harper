use std::collections::HashSet;

use json::JsonValue;
use url::Url;

pub fn list_domains(value: &JsonValue) -> Vec<String> {
    let mut urls: HashSet<String> = HashSet::new();
    if let JsonValue::Array(entries) = &value["log"]["entries"] {
        for entry in entries {
            let url_json = &entry["request"]["url"];
            let url_str = match url_json {
                JsonValue::String(s) => Some(s.as_str()),
                JsonValue::Short(s) => Some(s.as_str()),
                _ => None,
            };

            if let Some(host) = match url_str {
                Some(url) => match Url::parse(url) {
                    Ok(parsed_url) => parsed_url.host_str().map(|x| x.to_string()),
                    Err(_) => continue,
                },
                None => {
                    eprintln!("BAD JSON FOR URL: {:?}", url_json);
                    continue;
                }
            } {
                urls.insert(host);
            }
        }
    }
    urls.into_iter().collect()
}
