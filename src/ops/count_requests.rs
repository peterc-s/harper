use json::JsonValue;

pub fn get_counts(value: &JsonValue) -> usize {
    value["log"]["entries"].len()
}
