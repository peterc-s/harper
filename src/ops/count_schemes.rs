use crate::Har;
use std::collections::HashMap;
use url::Url;

pub fn get_counts(har: &Har, counts: &mut HashMap<String, usize>) {
    for entry in &har.log.entries {
        let url_str = &entry.request.url;
        let count_key = match Url::parse(url_str) {
            Ok(parsed_url) => parsed_url.scheme().to_string(),
            Err(_) => {
                eprintln!("Invalid URL format: {}", url_str);
                "Bad URL".into()
            }
        };
        *counts.entry(count_key).or_insert(0) += 1;
    }
}
