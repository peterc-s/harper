use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use chrono::{DateTime, Local};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use colored::Colorize;
use serde_json::{self, error::Category};
use std::{
    cmp::Reverse,
    collections::HashMap,
    fs,
    io::{self, IsTerminal, Read},
    process::ExitCode,
};
use tldextract::TldOption;

mod ops;
use ops::{
    blocklist, count_requests, count_schemes, count_urls, dns, filter, list_domains, search_for,
};

mod har;
use har::Har;

#[derive(Parser, Debug)]
#[command(version, about = "Command line HAR analyser.", long_about = None)]
struct Args {
    #[arg(short, long, help = "Filters out requests after the time.", default_value = None, global = true)]
    before: Option<DateTime<Local>>,

    #[arg(short, long, help = "Filters out requests before the time.", default_value = None, global = true)]
    after: Option<DateTime<Local>>,

    #[clap(subcommand)]
    command: Commands,

    /// Input HAR file (use '-' for stdin).
    #[arg(default_value = "-")]
    file: String,
}

#[derive(Subcommand, Debug)]
#[command(arg_required_else_help = true)]
enum Commands {
    /// Count number of times a request is sent to a URL.
    CountUrls(CountUrlArgs),

    /// Lists domains in the HAR.
    ListDomains,

    /// Count number of each scheme in the HAR.
    CountSchemes,

    /// Count the number of requests made.
    CountRequests,

    /// Search for a specific string.
    SearchFor(SearchForArgs),

    /// Return the contents of the HAR.
    Output,

    /// Check if URLs contained in the HAR are using DNSSEC.
    DNSSECAudit,

    /// Lookup common DNS record types of URLs contained in the HAR.
    DNSLookup,

    /// Downloads common blocklists, use '-' for FILE.
    GetBlockLists,

    /// Deletes block lists.
    RemoveBlockLists,

    /// Checks for URLs in common blocklists.
    BlockList,
}

#[derive(Debug, clap::Args)]
struct CountUrlArgs {
    #[arg(short, long, help="Method used for sorting, sorting is done at each level of the domain tree.", default_value = SortBy::Frequency.as_ref())]
    sort: SortBy,

    #[arg(
        short,
        long,
        help = "Merge the tld and the sld, i.e. merge example and .com"
    )]
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

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    if let Err(e) = run().await {
        eprintln!("{}: {:#}", "Error".red().bold(), e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[allow(unreachable_code)]
fn read_input(file_path: &String) -> Result<String> {
    fs::read_to_string(file_path).with_context(|| format!("Failed to read file: {}", file_path))
}

fn parse_har(input: &str) -> Result<Har> {
    // parse the file
    serde_json::from_str(input)
        .map_err(|e| {
            // on error, get 1-based line and column number of error
            let line = e.line();
            let column = e.column();

            // get error string and class
            let err_str = e.to_string();
            let error_class = e.classify();

            // get surrounding lines of context
            let lines: Vec<&str> = input.lines().collect();
            let line_index = line.saturating_sub(1);
            let start = line_index.saturating_sub(5);
            let end = (line_index + 5).min(lines.len());
            let context_lines = lines.get(start..end).unwrap_or_default();
            let error_line_in_context = line_index.saturating_sub(start);

            let mut context_str = String::new();
            for (i, line) in context_lines.iter().enumerate() {
                // add source
                context_str.push_str(line);
                context_str.push('\n');

                // add line pointer
                if i == error_line_in_context {
                    let pointer = format!(
                        "{}{}",
                        " ".repeat(column.saturating_sub(1)),
                        "^-- Error occurred here".purple().bold()
                    );
                    context_str.push_str(&pointer);
                    context_str.push('\n');
                }
            }

            // cleanup trailing newline
            if context_str.ends_with('\n') {
                context_str.pop();
            }

            // create error message based off error class
            let error_msg = match error_class {
                Category::Syntax => format!(
                    "{}: {}",
                    "JSON syntax error".red().bold(),
                    err_str.split(" at ").next().unwrap_or(&err_str)
                ),
                Category::Eof => "Unexpected end of JSON input".red().bold().to_string(),
                Category::Data => {
                    if let Some(field) = err_str
                        .strip_prefix("missing field `")
                        .and_then(|s| s.split('`').next())
                    {
                        format!("{}: `{}`", "Missing required field".red().bold(), field)
                    } else {
                        format!("{}: {}", "Data validation error".red().bold(), err_str)
                    }
                }
                _ => format!("{}: {}", "JSON parsing error".red().bold(), err_str),
            };

            anyhow!(
                "HAR validation failed at line {line}:{column}\n\
             {}\n\
             {}:\n{}\n",
                error_msg,
                "Context".yellow().bold(),
                context_str
            )
        })
        .context("Failed to parse HAR file")
}

async fn run() -> Result<()> {
    let args = Args::parse();

    match &args.command {
        Commands::GetBlockLists => return blocklist::download_all_blocklists().await,
        Commands::RemoveBlockLists => return blocklist::remove_blocklists(),
        _ => {}
    }

    let contents = match args.file {
        stdin if stdin == "-" => {
            let mut stdin = io::stdin();
            if stdin.is_terminal() {
                #[allow(unreachable_code)]
                return Err(Args::command()
                    .error(
                        ErrorKind::MissingRequiredArgument,
                        "Missing required argument: either provide a file or pipe input.",
                    )
                    .exit());
            }

            let mut contents = String::new();
            stdin.read_to_string(&mut contents)?;
            contents
        }
        file => read_input(&file)?,
    };

    let mut parsed = parse_har(&contents)?;

    if let Some(dt) = args.before {
        filter::filter_by_time(&mut parsed, dt, false);
    }

    if let Some(dt) = args.after {
        filter::filter_by_time(&mut parsed, dt, true);
    }

    match args.command {
        Commands::CountUrls(count_args) => {
            let tld_extractor = TldOption::default()
                .cache_path(".tld_cache")
                .private_domains(false)
                .update_local(false)
                .naive_mode(false)
                .build();

            let mut domain_tree = count_urls::DomainNode::default();
            count_urls::build_domain_tree(
                &parsed,
                &mut domain_tree,
                &tld_extractor,
                count_args.merge_tld,
            );

            match count_args.sort {
                SortBy::Alpha => {
                    count_urls::print_tree(&domain_tree, &mut |(name, _)| name.to_string());
                }
                SortBy::Frequency => {
                    count_urls::print_tree(&domain_tree, &mut |(_, node)| Reverse(node.count));
                }
            }
        }

        Commands::ListDomains => {
            let domains = list_domains::list_domains(&parsed);
            for domain in domains {
                println!("{}", domain);
            }
        }

        Commands::CountSchemes => {
            let mut counts = HashMap::new();
            count_schemes::get_counts(&parsed, &mut counts);

            let mut counts_vec: Vec<(&String, &usize)> = counts.iter().collect();
            counts_vec.sort_by_key(|a| Reverse(a.1));

            for (scheme, count) in counts_vec {
                println!("{}: {}", scheme, count);
            }
        }

        Commands::CountRequests => {
            let count = count_requests::get_counts(&parsed);

            println!("Found {} requests.", count);
        }

        Commands::SearchFor(search_args) => {
            let matches = search_for::search_for(&parsed, &search_args.string);
            for result in matches {
                println!("Found in request {}:", result.request_num);
                println!(
                    "Time: {}\nURL: {}\nMethod: {}\nIn fields: {:?}\n",
                    result.time, result.url, result.method, result.in_fields
                );
            }

            let b64_search_string = BASE64_STANDARD_NO_PAD.encode(&search_args.string);
            let matches_b64 = search_for::search_for(&parsed, &b64_search_string);
            for result in matches_b64 {
                println!("Found base64 encoded in request {}:", result.request_num);
                println!(
                    "Time: {}\nURL: {}\nMethod: {}\nIn fields: {:?}\n",
                    result.time, result.url, result.method, result.in_fields
                );
            }
        }

        Commands::Output => {
            println!("{}", json::stringify_pretty(json::parse(&contents)?, 4));
        }

        Commands::DNSSECAudit => dns::dnssec_audit(&parsed).await?,

        Commands::DNSLookup => dns::dns_lookup(&parsed).await?,

        Commands::GetBlockLists => unreachable!(),

        Commands::RemoveBlockLists => unreachable!(),

        Commands::BlockList => blocklist::check_blocklists(&parsed)?,
    }

    Ok(())
}
