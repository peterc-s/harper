use std::collections::HashSet;

use crate::Har;
use url::Url;

pub fn list_domains(har: &Har) -> Vec<String> {
    let mut urls: HashSet<String> = HashSet::new();
    for entry in &har.log.entries {
        let url_str = &entry.request.url;

        if let Some(host) = match Url::parse(url_str) {
            Ok(parsed_url) => parsed_url.host_str().map(|x| x.to_string()),
            Err(_) => continue,
        } {
            urls.insert(host);
        }
    }

    urls.into_iter().collect()
}
