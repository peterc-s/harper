use anyhow::{Context, Result, anyhow};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand, error::ErrorKind, CommandFactory};
use colored::Colorize;
use std::{
    cmp::Reverse,
    collections::HashMap,
    fs,
    io::{self, IsTerminal, Read},
    process::ExitCode,
};
use tldextract::TldOption;
use serde_json;

mod ops;
use ops::{count_requests, count_schemes, count_urls, filter, search_for};

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
enum Commands {
    /// Count number of times a request is sent to a URL.
    CountUrls(CountUrlArgs),

    /// Count number of each scheme in the HAR.
    CountSchemes,

    /// Count the number of requests made.
    CountRequests,

    /// Search for a specific string.
    SearchFor(SearchForArgs),

    /// Return the contents of the HAR.
    Output,
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

fn main() -> ExitCode {
    env_logger::init();

    if let Err(e) = run() {
        eprintln!("{}: {:#}", "Error".red().bold(), e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[allow(unreachable_code)]
fn read_input(file_path: &String) -> Result<String> {
    fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path))
}

fn parse_har(input: &str) -> Result<Har> {
    // parse the file
    serde_json::from_str(input).map_err(|e| {
        // on error, get 1-based line and column number of error
        let line = e.line();
        let column = e.column();

        // get missing field name
        let err_str = e.to_string();
        let field_name = err_str
            .split("missing field `")
            .nth(1)
            .and_then(|s| s.split('`').next())
            .unwrap_or("unknown field");

        // prepare context lines
        let lines: Vec<&str> = input.lines().collect();
        // go to 0-based
        let line_index = line.saturating_sub(1);
        // show 5 lines before
        let start = line_index.saturating_sub(5);
        // show 5 lines after
        let end = (line_index + 5).min(lines.len());

        // build context display
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
                    " ".repeat(column.saturating_sub(1)), // alignment
                    "^-- Expected field here".purple().bold()
                );
                context_str.push_str(&pointer);
                context_str.push('\n');
            }
        }

        // cleanup trailing newline
        if context_str.ends_with('\n') {
            context_str.pop();
        }

        anyhow!(
            "validation failed at line {line}:{column}\n\
             {}: `{field_name}`\n\
             {}:\n{}\n",
            "Missing required field".red().bold(),
            "Context".yellow().bold(),
            context_str
        )
    }).context("Failed to parse HAR file")
}

fn run() -> Result<()> {
    let args = Args::parse();

    let contents = match args.file {
        stdin if stdin == "-" => {
            let mut stdin = io::stdin();
            if stdin.is_terminal() {
                #[allow(unreachable_code)]
                return Err(Args::command()
                    .error(
                        ErrorKind::MissingRequiredArgument,
                        "Missing required argument: either provide a file or pipe input."
                    )
                    .exit());
            }
            
            let mut contents = String::new();
            stdin.read_to_string(&mut contents)?;
            contents
        },
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
    }

    Ok(())
}
