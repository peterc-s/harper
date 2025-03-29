use std::collections::HashMap;

use json::JsonValue;
use tldextract::TldExtractor;
use url::Url;

pub fn get_domain_tree(
    value: &JsonValue,
    domain_tree: &mut HashMap<String, HashMap<String, usize>>,
    tld_extractor: &TldExtractor,
) {
    match value {
        JsonValue::Object(map) => {
            for (key, val) in map.iter() {
                // look for "url" fields
                if key == "url" {
                    if let Some(url) = val.as_str() {
                        // parse the url
                        if let Ok(parsed_url) = Url::parse(url) {
                            // get the host name
                            if let Some(domain) = parsed_url.host_str() {
                                match tld_extractor.extract(domain) {
                                    Ok(res) => {
                                        domain_tree
                                            .entry(
                                                res.domain.unwrap_or_default()
                                                    + "."
                                                    + &res.suffix.unwrap_or_default().to_string(),
                                            )
                                            .or_insert_with(HashMap::new)
                                            .entry(res.subdomain.unwrap_or_default())
                                            .and_modify(|count| *count += 1)
                                            .or_insert(1);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                // continue recursively parsing
                get_domain_tree(val, domain_tree, tld_extractor);
            }
        }
        JsonValue::Array(arr) => {
            for item in arr {
                // recursively parse each value in the array
                get_domain_tree(item, domain_tree, tld_extractor);
            }
        }
        _ => {}
    }
}

pub fn get_domain_tree_full(
    value: &JsonValue,
    domain_tree: &mut HashMap<String, HashMap<String, HashMap<String, usize>>>,
    tld_extractor: &TldExtractor,
) {
    match value {
        JsonValue::Object(map) => {
            for (key, val) in map.iter() {
                // look for "url" fields
                if key == "url" {
                    if let Some(url) = val.as_str() {
                        // parse the url
                        if let Ok(parsed_url) = Url::parse(url) {
                            // get the host name
                            if let Some(domain) = parsed_url.host_str() {
                                match tld_extractor.extract(domain) {
                                    Ok(res) => {
                                        domain_tree
                                            .entry(res.suffix.unwrap_or_default())
                                            .or_insert_with(HashMap::new)
                                            .entry(res.domain.unwrap_or_default())
                                            .or_insert_with(HashMap::new)
                                            .entry(res.subdomain.unwrap_or_default())
                                            .and_modify(|count| *count += 1)
                                            .or_insert(1);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                // continue recursively parsing
                get_domain_tree_full(val, domain_tree, tld_extractor);
            }
        }
        JsonValue::Array(arr) => {
            for item in arr {
                // recursively parse each value in the array
                get_domain_tree_full(item, domain_tree, tld_extractor);
            }
        }
        _ => {}
    }
}

fn get_total_count(sub_map: &HashMap<String, HashMap<String, usize>>) -> usize {
    sub_map
        .values()
        .map(|subdomains| subdomains.values().sum::<usize>())
        .sum()
}

pub fn print_sorted_with_full<F, K>(
    domain_tree: &HashMap<String, HashMap<String, HashMap<String, usize>>>,
    mut sort_closure: F,
    indent: usize,
) where
    F: FnMut(&(&String, usize)) -> K,
    K: Ord,
{
    let mut tlds: Vec<(&String, usize)> = domain_tree
        .iter()
        .map(|(tld, slds)| (tld, get_total_count(slds)))
        .collect();
    tlds.sort_by_key(&mut sort_closure);

    for (tld, tld_count) in tlds {
        println!("{} ({})", tld, tld_count);

        let mut slds: Vec<(&String, usize)> = domain_tree[tld]
            .iter()
            .map(|(sld, subdomains)| (sld, subdomains.values().sum::<usize>()))
            .collect();
        slds.sort_by_key(&mut sort_closure);

        for (sld, sld_count) in slds {
            println!("{:indent$}  {} ({})", "", sld, sld_count, indent = indent);

            let mut subdomains: Vec<(&String, usize)> =
                domain_tree[tld][sld].iter().map(|(a, b)| (a, *b)).collect();
            subdomains.sort_by_key(&mut sort_closure);

            for (sub, count) in subdomains {
                println!(
                    "{:indent$}    {} ({})",
                    "",
                    sub,
                    count,
                    indent = indent + indent
                );
            }
        }
    }
}

pub fn print_sorted_with<F, K>(
    domain_tree: &HashMap<String, HashMap<String, usize>>,
    mut sort_closure: F,
    indent: usize,
) where
    F: FnMut(&(&String, usize)) -> K,
    K: Ord,
{
    let mut sld_tlds: Vec<(&String, usize)> = domain_tree
        .iter()
        .map(|(sld_tld, subdomain)| (sld_tld, subdomain.values().sum::<usize>()))
        .collect();
    sld_tlds.sort_by_key(&mut sort_closure);

    for (sld_tld, sld_tld_count) in sld_tlds {
        println!("{} ({})", sld_tld, sld_tld_count);

        let mut subdomains: Vec<(&String, usize)> =
            domain_tree[sld_tld].iter().map(|(a, b)| (a, *b)).collect();
        subdomains.sort_by_key(&mut sort_closure);

        for (sub, count) in subdomains {
            println!("{:indent$}    {} ({})", "", sub, count, indent = indent);
        }
    }
}
