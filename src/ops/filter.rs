use chrono::{DateTime, Local};
use json::JsonValue;

pub fn filter_by_time(value: &mut JsonValue, time: DateTime<Local>, after: bool) -> Option<()> {
    let log = match value {
        JsonValue::Object(object) => object.get_mut("log")?,
        _ => {
            return None;
        }
    };

    let entries = match log {
        JsonValue::Object(object) => object.get_mut("entries")?,
        _ => {
            return None;
        }
    };

    let JsonValue::Array(entries) = entries else {
        return None;
    };

    entries.retain(|entry| {
        let entry = match entry {
            JsonValue::Object(object) => object,
            _ => return false,
        };
        let start_time = match entry.get("startedDateTime").map(|x| x.as_str()) {
            Some(Some(s)) => s,
            _ => return false,
        };
        let Ok(start_time) = DateTime::parse_from_rfc3339(start_time) else {
            return false;
        };

        if after {
            start_time >= time
        } else {
            start_time <= time
        }
    });
    Some(())
}
