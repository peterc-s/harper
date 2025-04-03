use anyhow::Result;
use colored::Colorize;
use hickory_resolver::{
    proto::rr::{Record, RecordType},
    Resolver, TokioResolver,
};

use crate::har::Har;

use super::list_domains;

pub async fn dnssec_audit(har: &Har) -> Result<()> {
    let mut domains: Vec<String> = list_domains::list_domains(har);
    domains.sort_by_key(|x| x.chars().rev().collect::<String>());

    let resolver = Resolver::builder_tokio()?.build();

    for domain in domains {
        let resp = resolver.lookup(domain.clone() + ".", RecordType::ANY);
        let Ok(resp) = resp.await else {
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

async fn get_dns_records(resolver: &TokioResolver, domain: &str) -> Vec<Record> {
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
    let mut records = Vec::new();

    for rt in record_types {
        match resolver.lookup(&fqdn, rt).await {
            Ok(response) => {
                records.extend(response.records().iter().cloned());
            },
            Err(_) => {},
        }
    }

    records
}

pub async fn dns_lookup(har: &Har) -> Result<()> {
    let mut domains: Vec<String> = list_domains::list_domains(har);
    domains.sort_by_key(|x| x.chars().rev().collect::<String>());

    let resolver = Resolver::builder_tokio()?.build();

    for domain in domains {
        println!("{}:", domain.bold().blue());

        let mut found_records = false;

        for record in get_dns_records(&resolver, &domain).await {
            found_records = true;
            println!(
                "[{:6}] {} - TTL: {} - {}",
                format!("{}", record.record_type()).purple().bold(),
                record.name().to_string().cyan(),
                record.ttl().to_string().yellow(),
                record
                    .data()
                    .to_string()
            );
        }

        if !found_records {
            println!("{}", "No DNS records found".red());
        }

        println!();
    }

    Ok(())
}
