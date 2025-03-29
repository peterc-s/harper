use std::collections::HashMap;

use json::JsonValue;
use url::Url;

pub fn get_counts(value: &JsonValue, counts: &mut HashMap<String, usize>) {
    if let JsonValue::Array(entries) = &value["log"]["entries"] {
        for entry in entries {
            let url_json = &entry["request"]["url"];
            let url_str = match url_json {
                JsonValue::String(s) => Some(s.as_str()),
                JsonValue::Short(s) => Some(s.as_str()),
                _ => None,
            };

            let count_key = match url_str {
                Some(url) => match Url::parse(url) {
                    Ok(parsed_url) => parsed_url.scheme().to_string(),
                    Err(_) => "Bad URL".into(),
                },
                None => {
                    eprintln!("BAD JSON FOR URL: {:?}", url_json);
                    "Bad JSON".into()
                }
            };

            *counts.entry(count_key).or_insert(0) += 1;
        }
    }
}
