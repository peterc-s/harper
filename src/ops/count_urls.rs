use std::{collections::HashMap, net::IpAddr};
use tldextract::TldExtractor;
use url::Url;
use crate::Har;

#[derive(Debug, Default)]
pub struct DomainNode {
    pub count: usize,
    pub children: HashMap<String, DomainNode>,
}

pub fn build_domain_tree(
    har: &Har,
    tree: &mut DomainNode,
    tld_extractor: &TldExtractor,
    merge_tld: bool,
) {
    // iterate through URLs in entries in HAR
    for entry in &har.log.entries {
        let url = &entry.request.url;
        process_url(url, tree, tld_extractor, merge_tld);
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

    // get parts of URL
    let parts = if parsed_url.scheme() == "data" {
        // if using data scheme, use "data:" as though it were a TLD
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

    // add the parts to the tree
    let mut current = tree;
    for part in parts {
        current = current.children.entry(part).or_default();
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
    match (merge_tld, &extracted.domain, &extracted.suffix) {
        (true, Some(domain), Some(suffix)) => parts.push(format!("{}.{}", domain, suffix)),
        (true, None, Some(suffix)) => parts.push(suffix.clone()),
        (true, Some(domain), None) => parts.push(domain.clone()),
        (false, _, Some(suffix)) => {
            parts.push(suffix.clone());
            if let Some(domain) = &extracted.domain {
                parts.push(domain.clone());
            }
        }
        _ => (),
    }

    // add subdomain
    if let Some(subdomain) = &extracted.subdomain {
        parts.extend(
            subdomain
                .split('.')
                .rev()
                .map(String::from)
        );
    } else {
        parts.push(String::new())
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
