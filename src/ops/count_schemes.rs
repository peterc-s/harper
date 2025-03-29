use std::collections::HashMap;

use json::JsonValue;
use url::Url;

pub fn get_counts(value: &JsonValue, counts: &mut HashMap<String, usize>) {
    match value {
        JsonValue::Object(map) => {
            for (key, val) in map.iter() {
                // look for "url" fields
                if key == "url" {
                    if let JsonValue::String(url) = val {
                        // parse the url
                        if let Ok(parsed_url) = Url::parse(url) {
                            // get the host name
                            counts
                                .entry(parsed_url.scheme().to_string())
                                .and_modify(|count| *count += 1)
                                .or_insert(1);
                        }
                    }
                }

                // continue recursively parsing
                get_counts(val, counts);
            }
        }
        JsonValue::Array(arr) => {
            for item in arr {
                // recursively parse each value in the array
                get_counts(item, counts);
            }
        }
        _ => {}
    }
}
