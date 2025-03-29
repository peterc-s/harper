use json::JsonValue;
use std::{collections::HashMap, net::IpAddr};
use tldextract::TldExtractor;
use url::Url;

#[derive(Debug, Default)]
pub struct DomainNode {
    pub count: usize,
    pub children: HashMap<String, DomainNode>,
}

pub fn build_domain_tree(
    har_data: &JsonValue,
    tree: &mut DomainNode,
    tld_extractor: &TldExtractor,
    merge_tld: bool,
) {
    // get entries array from HAR
    let entries = match &har_data["log"]["entries"] {
        JsonValue::Array(arr) => arr,
        _ => {
            println!("Invalid HAR structure - missing log.entries.");
            return;
        }
    };

    // iterate through entries
    for entry in entries {
        // get request part
        let request = match &entry["request"] {
            JsonValue::Object(obj) => obj,
            _ => {
                eprintln!("Entry missing request object");
                continue;
            }
        };

        // get url from request part
        let url = match &request["url"] {
            JsonValue::String(s) => s,
            JsonValue::Short(s) => s.as_str(),
            _ => {
                eprintln!("Request missing valid URL");
                continue;
            }
        };
        
        // process the URL, adding it into the tree
        process_url(&url, tree, tld_extractor, merge_tld);
    }
}

fn process_url(
    url_str: &str,
    tree: &mut DomainNode,
    tld_extractor: &TldExtractor,
    merge_tld: bool,
) {
    // parse URL
    let Ok(parsed_url) = Url::parse(url_str) else {
        eprintln!("Failed to parse URL: {}", url_str);
        return;
    };

    // get parts of a url
    let parts = if parsed_url.scheme() == "data" {
        // if it's schema is data, just use data:
        vec!["data:".to_string()]
    } else {
        // get host from parsed url
        let Some(host) = parsed_url.host_str() else {
            eprintln!("URL has no host: {}", parsed_url);
            return;
        };

        // get the parts of the host string
        get_domain_parts(host, tld_extractor, merge_tld)
    };

    // add parts to the tree
    let mut current = tree;
    for part in parts {
        current = current
            .children
            .entry(part)
            .or_default();
        current.count += 1;
    }
}

fn get_domain_parts(host: &str, tld_extractor: &TldExtractor, merge_tld: bool) -> Vec<String> {
    // handle IP addresses
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![format!("ip:{}", ip)];
    }

    // handle invalid results
    let Ok(extracted) = tld_extractor.extract(host) else {
        eprintln!("Failed to extract TLD from: {}", host);
        return vec![format!("invalid:{}", host)];
    };

    let mut parts = Vec::new();

    // add domain and suffix
    if merge_tld {
        if let (Some(domain), Some(suffix)) = (&extracted.domain, &extracted.suffix) {
            parts.push(format!("{}.{}", domain, suffix));
        } else if let Some(suffix) = &extracted.suffix {
            parts.push(suffix.to_string());
        } else if let Some(domain) = &extracted.domain {
            parts.push(domain.to_string());
        }
    } else {
        if let Some(suffix) = &extracted.suffix {
            parts.push(suffix.to_string());
        }
        if let Some(domain) = &extracted.domain {
            parts.push(domain.to_string());
        }
    }

    // add subdomain
    if let Some(subdomain) = &extracted.subdomain {
        let mut sub_parts: Vec<_> = subdomain
            .split('.')
            .collect();
        sub_parts.reverse();
        parts.extend(
            sub_parts
                .into_iter()
                .map(|s| s.to_string())
        );
    } else {
        parts.push("".into());
    }

    // if none of the parts exist
    if parts.is_empty() {
        parts.push("unknown".to_string());
    }

    parts
}

pub fn print_tree<F, K>(node: &DomainNode, sort_closure: &mut F)
where
    F: FnMut(&(&String, &DomainNode)) -> K,
    K: Ord,
{
    // recursively print the tree levels
    print_level(&node.children, 0, sort_closure);
}

fn print_level<F, K>(children: &HashMap<String, DomainNode>, depth: usize, sort_closure: &mut F)
where
    F: FnMut(&(&String, &DomainNode)) -> K,
    K: Ord,
{
    // get entries as a vector
    let mut entries: Vec<_> = children.iter().collect();
    // sort them
    entries.sort_by_key(|e| sort_closure(e));

    // iterate through entries
    for (key, node) in entries {
        // print each entry
        let indent = "    ".repeat(depth);
        println!("{}{} ({})", indent, key, node.count);

        // print its children
        print_level(&node.children, depth + 1, sort_closure);
    }
}
