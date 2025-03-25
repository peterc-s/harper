use std::{cmp::Reverse, collections::HashMap};
use std::fs;

use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};

mod ops;
use ops::search_for::search_for;
use ops::{count_requests, count_schemes, count_urls};
use tldextract::TldOption;

#[derive(Parser, Debug)]
#[command(version, about = "Command line HAR analyser.", long_about = None)]
struct Args {
    /// The HAR file to analyse.
    file: String,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Count number of times a request is sent to a URL.
    CountUrls(CountUrlArgs),

    /// Count number of each scheme in the HAR.
    CountSchemes,

    /// Count the number of requests made.
    CountRequests,

    /// Search for a specific string.
    SearchFor(SearchForArgs),
}

#[derive(Debug, clap::Args)]
struct CountUrlArgs {
    #[arg(short, long, help="Method used for sorting, sorting is done at each level of the domain tree.", default_value = SortBy::Frequency.as_ref())]
    sort: SortBy,
    
    #[arg(short, long, help="Merge the tld and the sld, i.e. merge example and .com")]
    merge_tld: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum SortBy {
    /// Sort alphanumerically at each level.
    Alpha,

    /// Sort by frequency at each level.
    Frequency,
}

impl AsRef<str> for SortBy {
    fn as_ref(&self) -> &str {
        match self {
            SortBy::Frequency => "frequency",
            SortBy::Alpha => "alpha",
        }
    }
}

#[derive(Debug, clap::Args)]
struct SearchForArgs {
    /// The string to search for.
    string: String,
}

fn main() {
    let args = Args::parse();

    let contents = fs::read_to_string(args.file)
        .expect("Could not read file at {file_name}.");

    let parsed = json::parse(&contents)
        .expect("Could not parse file as json.");

    match args.command {
        Commands::CountUrls(count_args) => {
            let tld_extractor = TldOption::default()
                .cache_path(".tld_cache")
                .private_domains(false)
                .update_local(false)
                .naive_mode(false)
                .build();

            match count_args.sort {
                SortBy::Alpha => {
                    if count_args.merge_tld {
                        let mut domain_tree = HashMap::new();
                        count_urls::get_domain_tree(&parsed, &mut domain_tree, &tld_extractor);
                        count_urls::print_sorted_with(&domain_tree, |a| a.0.clone(), 4);
                    } else {
                        let mut domain_tree = HashMap::new();
                        count_urls::get_domain_tree_full(&parsed, &mut domain_tree, &tld_extractor);
                        count_urls::print_sorted_with_full(&domain_tree, |a| a.0.clone(), 4);
                    }
                },
                SortBy::Frequency => {
                    if count_args.merge_tld {
                        let mut domain_tree = HashMap::new();
                        count_urls::get_domain_tree(&parsed, &mut domain_tree, &tld_extractor);
                        count_urls::print_sorted_with(&domain_tree, |a| Reverse(a.1), 4);
                    } else {
                        let mut domain_tree = HashMap::new();
                        count_urls::get_domain_tree_full(&parsed, &mut domain_tree, &tld_extractor);
                        count_urls::print_sorted_with_full(&domain_tree, |a| Reverse(a.1), 4);
                    }
                },
            }
        },

        Commands::CountSchemes => {
            let mut counts = HashMap::new();
            count_schemes::get_counts(&parsed, &mut counts);

            let mut counts_vec: Vec<(&String, &usize)> = counts
                .iter()
                .map(|(a, b)| (a, b))
                .collect();
            counts_vec.sort_by_key(|a| Reverse(a.1));

            for (scheme, count) in counts_vec {
                println!("{}: {}", scheme, count);
            }
        },

        Commands::CountRequests => {
            let count = count_requests::get_counts(&parsed);

            println!("Found {} requests.", count);
        },

        Commands::SearchFor(search_args) => {
            let matches = search_for(&parsed, &search_args.string);
            for result in matches {
                println!("Found in request {}:", result.request_num);
                println!("Time: {}\nURL: {}\nMethod: {}\nIn fields: {:?}\n", result.time, result.url, result.method, result.in_fields);
            }

            let b64_search_string = BASE64_STANDARD_NO_PAD.encode(&search_args.string);
            let matches_b64 = search_for(&parsed, &b64_search_string);
            for result in matches_b64 {
                println!("Found base64 encoded in request {}:", result.request_num);
                println!("Time: {}\nURL: {}\nMethod: {}\nIn fields: {:?}\n", result.time, result.url, result.method, result.in_fields);
            }
        },
    }
}
