use anyhow::{Result, Context};
use hickory_resolver::{proto::rr::{Record, RecordType}, Resolver};
use colored::Colorize;

use crate::har::Har;

use super::list_domains;

pub fn dnssec_audit(har: &Har) -> Result<()> {
    let mut domains: Vec<String> = list_domains::list_domains(&har);
    domains.sort_by_key(|x| x.chars().rev().collect::<String>());

    let (config, opts) = hickory_resolver::system_conf::read_system_conf()
        .context("Failed to read system DNS config.")?;
    let resolver = Resolver::new(config, opts)
        .context("Failed to create resolver.")?;

    for domain in domains {
        let resp = resolver.lookup(domain.clone() + ".", RecordType::ANY);
        let Ok(resp) = resp else {
            println!("{}: {}", domain.bold(), "DNS lookup failed".red());
            continue;
        };

        let mut sig_found = false;

        for record in resp.records() {
            sig_found |= record.record_type() == RecordType::RRSIG;
        }

        if sig_found {
            println!("{}: {}", domain.bold(), "Signature found.".green())
        } else {
            println!("{}: {}", domain.bold(), "No signature found.".yellow())
        }
    }

    Ok(())
}

fn get_dns_records<'a>(resolver: &'a Resolver, domain: &'a str) -> impl Iterator<Item = Record> + 'a {
    let record_types = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::ANAME,
        RecordType::CNAME,
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::RRSIG,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TXT,
    ];

    let fqdn = format!("{}.", domain.trim_end_matches('.'));
    
    record_types.into_iter()
        .filter_map(move |rt| 
            resolver
                .lookup(&fqdn, rt)
                .ok()
        )
        .flat_map(|response|
            response
                .records()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        )
}

pub fn dns_lookup(har: &Har) -> Result<()> {
    let mut domains: Vec<String> = list_domains::list_domains(&har);
    domains.sort_by_key(|x| x.chars().rev().collect::<String>());

    let (config, opts) = hickory_resolver::system_conf::read_system_conf()
        .context("Failed to read system DNS config.")?;
    let resolver = Resolver::new(config, opts)
        .context("Failed to create resolver.")?;

    for domain in domains {
            println!("{}:", domain.bold().blue());
        
        let mut found_records = false;
        
        for record in get_dns_records(&resolver, &domain) {
            found_records = true;
            println!(
                "[{:6}] {} - TTL: {} - {}",
                format!("{}", record.record_type()).purple().bold(),
                record.name().to_string().cyan(),
                record.ttl().to_string().yellow(),
                record.data()
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "<no data>".to_string())
            );
        }
        
        if !found_records {
            println!("{}", "No DNS records found".red());
        }
        
        println!();}

    Ok(())
}
