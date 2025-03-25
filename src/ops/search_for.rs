use json::JsonValue;

#[derive(Clone, Debug)]
pub struct SearchResult<'a> {
    pub request_num: usize,
    pub time: String,
    pub url: String,
    pub method: String,
    pub in_fields: Vec<String>,
    pub request_json: &'a JsonValue,
}

pub fn search_for<'a>(value: &'a JsonValue, search_str: &String) -> Vec<SearchResult<'a>> {
    let mut out: Vec<SearchResult<'a>> = Vec::new();

    match &value["log"]["entries"] {
        JsonValue::Array(entries) => {
            for (i, entry) in entries.iter().enumerate() {
                let time = entry["startedDateTime"].to_string();

                let request = &entry["request"];
                let method = request["method"].to_string();
                let url = request["url"].to_string();
                let http_ver = request["httpVersion"].to_string();
                let headers_str = request["headers"].to_string();
                let cookies_str = request["cookies"].to_string();
                let query_str = request["queryString"].to_string();
                let post_data_str = request["postData"].to_string();

                let response = &entry["response"];
                let status = response["status"].to_string();
                let status_text = response["statusText"].to_string();
                let response_http_ver = response["httpVersion"].to_string();
                let response_headers_str = response["headers"].to_string();
                let response_cookies_str = response["cookies"].to_string();
                let content_str = response["content"].to_string();
                let redirect_url = response["redirectURL"].to_string();

                let mut in_fields = Vec::new();

                if time.contains(search_str) {
                    in_fields.push("time".to_string());
                }

                if method.contains(search_str) {
                    in_fields.push("request_method".to_string());
                }
                if url.contains(search_str) {
                    in_fields.push("request_url".to_string());
                }
                if http_ver.contains(search_str) {
                    in_fields.push("request_http_version".to_string());
                }
                if headers_str.contains(search_str) {
                    in_fields.push("request_headers".to_string());
                }
                if cookies_str.contains(search_str) {
                    in_fields.push("request_cookies".to_string());
                }
                if query_str.contains(search_str) {
                    in_fields.push("request_query_string".to_string());
                }
                if post_data_str.contains(search_str) {
                    in_fields.push("request_post_data".to_string());
                }

                if status.contains(search_str) {
                    in_fields.push("response_status".to_string());
                }
                if status_text.contains(search_str) {
                    in_fields.push("response_status_text".to_string());
                }
                if response_http_ver.contains(search_str) {
                    in_fields.push("response_http_version".to_string());
                }
                if response_headers_str.contains(search_str) {
                    in_fields.push("response_headers".to_string());
                }
                if response_cookies_str.contains(search_str) {
                    in_fields.push("response_cookies".to_string());
                }
                if content_str.contains(search_str) {
                    in_fields.push("response_content".to_string());
                }
                if redirect_url.contains(search_str) {
                    in_fields.push("response_redirect_url".to_string());
                }

                if !in_fields.is_empty() {
                    let result = SearchResult {
                        request_num: i + 1,
                        time: time.clone(),
                        url: url.clone(),
                        method: method.clone(),
                        in_fields,
                        request_json: request,
                    };
                    out.push(result);
                }
            }
        }
        _ => panic!("Invalid HAR file."),
    }

    out
}
