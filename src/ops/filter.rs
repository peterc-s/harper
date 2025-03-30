use chrono::{DateTime, Local};
use crate::Har;

pub fn filter_by_time(har: &mut Har, time: DateTime<Local>, after: bool) -> Option<()> {
    har.log.entries.retain(|entry| {
        let start_time = match DateTime::parse_from_rfc3339(&entry.started_date_time) {
            Ok(t) => t,
            Err(_) => return false,
        };

        if after {
            start_time >= time
        } else {
            start_time <= time
        }
    });
    
    Some(())
}
