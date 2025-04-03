use anyhow::{Context, Result};
use colored::Colorize;
use reqwest::Client;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use crate::har::Har;

use super::list_domains;

const BLOCKLISTS: [(&str, &str); 9] = [
    (
        "https://github.com/mullvad/dns-blocklists/raw/refs/heads/main/output/doh/doh_adblock.txt",
        "mullvad_doh_adblock.txt",
    ),
    (
        "https://github.com/mullvad/dns-blocklists/raw/refs/heads/main/output/doh/doh_adult.txt",
        "mullvad_doh_adult.txt",
    ),
    (
        "https://github.com/mullvad/dns-blocklists/raw/refs/heads/main/output/doh/doh_gambling.txt",
        "mullvad_doh_gambling.txt",
    ),
    (
        "https://github.com/mullvad/dns-blocklists/raw/refs/heads/main/output/doh/doh_privacy.txt",
        "mullvad_doh_privacy.txt",
    ),
    (
        "https://github.com/mullvad/dns-blocklists/raw/refs/heads/main/output/doh/doh_social.txt",
        "mullvad_doh_social.txt",
    ),
    (
        "https://v.firebog.net/hosts/Easyprivacy.txt",
        "firebog_easy_privacy.txt",
    ),
    ("https://small.oisd.nl/rpz", "oisd_small.txt"),
    (
        "https://v.firebog.net/hosts/AdguardDNS.txt",
        "adguard_dns.txt",
    ),
    ("https://nsfw.oisd.nl/rpz", "oist_nsfw.txt"),
];

async fn download_blocklist(
    url: &str,
    install_dir: &Path,
    path: &str,
    client: &Client,
) -> Result<()> {
    let response = client.get(url).send().await?;
    let content = response.text().await?;

    let mut blocklist_path = PathBuf::from(install_dir);
    blocklist_path.push(path);

    fs::write(blocklist_path, content)?;
    Ok(())
}

pub async fn download_all_blocklists() -> Result<()> {
    let client = Client::new();
    let exe_path = std::env::current_exe()?;
    let install_dir = exe_path
        .parent()
        .context("Couldn't get harper installation directory.")?;

    for (url, path) in BLOCKLISTS {
        println!(
            "{}: {} {} {}",
            "Downloading".purple(),
            url.cyan(),
            "as".dimmed(),
            path
        );
        download_blocklist(url, install_dir, path, &client).await?;
    }

    Ok(())
}

pub fn check_blocklists(har: &Har) -> Result<()> {
    let domains = list_domains::list_domains(har);

    let exe_path = std::env::current_exe()?;
    let install_dir = exe_path
        .parent()
        .context("Couldn't get harper installation directory.")?;

    for (_, filename) in BLOCKLISTS.iter() {
        let mut blocklist_domains = HashSet::new();

        let path = install_dir.join(filename);
        let content = fs::read_to_string(&path).with_context(|| {
            format!(
                "Failed to read blocklist: {:?}\nHave you run {}?\n{}",
                path,
                "harper [FILE] get-block-lists".green(),
                "Caused by".red().bold()
            )
        })?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
                continue;
            }

            blocklist_domains.insert(line);
        }

        println!("{}: {}", "Checking blocklist".blue().bold(), filename);
        for domain in &domains {
            let domain_lower = domain.to_lowercase();
            let parts: Vec<&str> = domain_lower.split('.').collect();
            let mut found = false;

            for i in 0..parts.len() {
                let suffix = parts[i..].join(".");
                if blocklist_domains.contains(&suffix.as_str()) {
                    found = true;
                    break;
                }
            }

            if found {
                println!("{}: {}", "Found".yellow(), domain.red())
            }
        }
        println!();
    }

    Ok(())
}
