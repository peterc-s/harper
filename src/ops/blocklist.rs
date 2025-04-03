use anyhow::{Context, Result};
use colored::Colorize;
use directories::ProjectDirs;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

use crate::har::Har;

use super::list_domains;

const BLOCKLISTS: [(&str, &str); 7] = [
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
    // ("https://small.oisd.nl/rpz", "oisd_small.txt"),
    (
        "https://v.firebog.net/hosts/AdguardDNS.txt",
        "adguard_dns.txt",
    ),
    // ("https://nsfw.oisd.nl/rpz", "oist_nsfw.txt"),
];

async fn download_blocklist(
    url: &str,
    install_dir: &Path,
    path: &str,
    client: &Client,
) -> Result<()> {
    // create progress bar
    let pb = ProgressBar::new(0);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("##-"));
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(format!("Downloading {}", path));

    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to send request to {}", url))?;

    // blocklist file path
    let mut blocklist_path = PathBuf::from(install_dir);
    blocklist_path.push(path);

    // create blocklist file
    let mut file = tokio::fs::File::create(&blocklist_path)
        .await
        .with_context(|| format!("Failed to create file: {:?}", blocklist_path))?;

    // update progress bar
    let mut downloaded: u64 = 0;
    if let Some(total) = response.content_length() {
        pb.set_length(total);
    }

    // download in chunks
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("Failed to read chunk from {}", url))?
    {
        file.write_all(&chunk)
            .await
            .with_context(|| format!("Failed to write chunk to {:?}", blocklist_path))?;

        // update progress bar
        let new = downloaded + chunk.len() as u64;
        downloaded = new;
        pb.set_position(new);
    }

    Ok(())
}

fn get_blocklists_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "peterc-s", "harper")
        .context("Failed to determine platform-specific project directories.")?;

    let data_dir = proj_dirs.data_dir();
    let blocklists_dir = data_dir.join("blocklists");

    if !blocklists_dir.exists() {
        fs::create_dir_all(&blocklists_dir).context("Failed to create blocklists directory")?;
    }

    Ok(blocklists_dir)
}

pub async fn download_all_blocklists() -> Result<()> {
    let client = Client::new();
    let blocklists_dir = get_blocklists_dir()?;

    for (url, path) in BLOCKLISTS {
        println!(
            "{}: {} {} {}",
            "Downloading".purple(),
            url.cyan(),
            "as".dimmed(),
            path
        );
        download_blocklist(url, &blocklists_dir, path, &client).await?;
    }

    Ok(())
}

pub fn check_blocklists(har: &Har) -> Result<()> {
    let domains = list_domains::list_domains(har);
    let blocklists_dir = get_blocklists_dir()?;

    for (_, filename) in BLOCKLISTS.iter() {
        let mut blocklist_domains = HashSet::new();

        let path = blocklists_dir.join(filename);
        let content = fs::read_to_string(&path).with_context(|| {
            format!(
                "Failed to read blocklist: {:?}\nHave you run {}?\n{}",
                path,
                "harper - get-block-lists".green(),
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
