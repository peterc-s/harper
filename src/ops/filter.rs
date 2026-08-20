use crate::Har;
use chrono::{DateTime, Local};

pub fn filter_by_time(har: &mut Har, time: DateTime<Local>, after: bool) {
    har.log.entries.retain(|entry| {
        let Ok(start_time) = DateTime::parse_from_rfc3339(&entry.started_date_time) else {
            return false;
        };

        if after {
            start_time >= time
        } else {
            start_time <= time
        }
    });
}
