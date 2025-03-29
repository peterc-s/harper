use json::JsonValue;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SearchResult<'a> {
    pub request_num: usize,
    pub time: String,
    pub url: String,
    pub method: String,
    pub in_fields: Vec<String>,
    pub request_json: &'a JsonValue,
}

pub fn search_for<'a>(value: &'a JsonValue, search_str: &str) -> Vec<SearchResult<'a>> {
    let mut out = Vec::new();

    let entries = match &value["log"]["entries"] {
        JsonValue::Array(entries) => entries,
        _ => panic!("Invalid HAR file."),
    };

    for (i, entry) in entries.iter().enumerate() {
        let mut in_fields = Vec::new();
        let request = &entry["request"];
        let response = &entry["response"];

        // field checking
        let mut check_fields = |parent: &JsonValue, fields: &[(&str, &str)], prefix: &str| {
            // iterate through different field names and their JSON equivalents
            for (field_name, json_path) in fields {
                // get the json value of the field
                let value = &parent[*json_path];

                // check if it contains the search string
                if value.to_string().contains(search_str) {
                    in_fields.push(format!("{}_{}", prefix, field_name));
                }
            }
        };

        // entry-level fields
        check_fields(
            entry,
            &[("time", "startedDateTime")],
            ""
        );

        // request fields
        check_fields(
            request,
            &[
                ("method", "method"),
                ("url", "url"),
                ("http_version", "httpVersion"),
                ("headers", "headers"),
                ("cookies", "cookies"),
                ("query_string", "queryString"),
                ("post_data", "postData"),
            ],
            "request"
        );

        // response fields
        check_fields(
            response,
            &[
                ("status", "status"),
                ("status_text", "statusText"),
                ("http_version", "httpVersion"),
                ("headers", "headers"),
                ("cookies", "cookies"),
                ("content", "content"),
                ("redirect_url", "redirectURL"),
            ],
            "response"
        );

        if !in_fields.is_empty() {
            out.push(SearchResult {
                request_num: i + 1,
                time: entry["startedDateTime"].to_string(),
                url: request["url"].to_string(),
                method: request["method"].to_string(),
                in_fields,
                request_json: request,
            });
        }
    }

    out
}
