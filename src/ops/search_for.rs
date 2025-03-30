use crate::har::{Har, Request};
use serde::Serialize;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SearchResult<'a> {
    pub request_num: usize,
    pub time: String,
    pub url: String,
    pub method: String,
    pub in_fields: Vec<String>,
    pub request: &'a Request,
}

macro_rules! check_fields {
    (
        $obj:expr,
        $prefix:expr,
        [$(($field:literal, $expr:expr)),+ $(,)?],
        $search_str:expr,
        $in_fields:expr
    ) => {
        $(
            check_serialised_field(
                $expr,
                $field,
                $search_str,
                $in_fields,
                $prefix,
            );
        )+
    };
    (
        $obj:expr,
        $prefix:expr,
        [$(($field:literal, $expr:expr, maybe)),+ $(,)?],
        $search_str:expr,
        $in_fields:expr
    ) => {
        $(
            if let Some(value) = $expr {
                check_serialised_field(
                    value,
                    $field,
                    $search_str,
                    $in_fields,
                    $prefix,
                );
            }
        )+
    };
}

fn check_serialised_field<T: Serialize>(
    value: &T,
    field_name: &str,
    search_str: &str,
    in_fields: &mut Vec<String>,
    prefix: &str,
) {
    if let Ok(json_str) = serde_json::to_string(value) {
        if json_str.contains(search_str) {
            let field = if prefix.is_empty() {
                field_name.to_string()
            } else {
                format!("{}_{}", prefix, field_name)
            };
            in_fields.push(field);
        }
    }
}

pub fn search_for<'a>(har: &'a Har, search_str: &'a str) -> Vec<SearchResult<'a>> {
    har.log
        .entries
        .iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let mut in_fields = Vec::new();
            let request = &entry.request;
            let response = &entry.response;

            // Entry-level fields
            check_serialised_field(
                &entry.started_date_time,
                "startedDateTime",
                search_str,
                &mut in_fields,
                "",
            );

            // Request fields
            check_fields!(
                request,
                "request",
                [
                    ("method", &request.method),
                    ("url", &request.url),
                    ("http_version", &request.http_version),
                    ("headers", &request.headers),
                    ("cookies", &request.cookies),
                    ("query_string", &request.query_string),
                    ("post_data", &request.post_data),
                ],
                search_str,
                &mut in_fields
            );

            // Response fields
            check_fields!(
                response,
                "response",
                [
                    ("status", &response.status),
                    ("status_text", &response.status_text),
                    ("http_version", &response.http_version),
                    ("headers", &response.headers),
                    ("cookies", &response.cookies),
                    ("content", &response.content),
                    ("redirect_url", &response.redirect_url),
                ],
                search_str,
                &mut in_fields
            );

            in_fields.is_empty().then(|| SearchResult {
                request_num: i + 1,
                time: entry.started_date_time.clone(),
                url: request.url.clone(),
                method: request.method.clone(),
                in_fields,
                request: &entry.request,
            })
        })
        .collect()
}
