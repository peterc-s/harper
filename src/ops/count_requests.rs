use crate::Har;

pub fn get_counts(har: &Har) -> usize {
    har.log.entries.len()
}
