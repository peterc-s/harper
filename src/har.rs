use serde::{Deserialize, Serialize, Deserializer, de::IntoDeserializer};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Har {
    pub log: Log,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub version: String,
    pub creator: Creator,
    pub browser: Option<Browser>,
    pub pages: Option<Vec<Page>>,
    pub entries: Vec<Entry>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Creator {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Browser {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    pub page_timings: PageTimings,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageTimings {
    pub on_content_load: Option<f64>,
    pub on_load: Option<f64>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub pageref: Option<String>,
    pub started_date_time: String,
    pub time: f64,
    pub request: Request,
    pub response: Response,
    pub cache: Cache,
    // this is a leniancy given, HAR 1.2 files
    // should have a Timing, but for some reason,
    // many Firefox generated don't.
    #[serde(deserialize_with = "deserialize_empty_object")]
    pub timings: Option<Timing>,
    pub server_ip_address: Option<String>,
    pub connection: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub query_string: Vec<QueryString>,
    pub post_data: Option<PostData>,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    // this is a leniancy given, HAR 1.2 files
    // should have content, but for some reason,
    // many Firefox generated don't.
    #[serde(deserialize_with = "deserialize_empty_object")]
    pub content: Option<Content>,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub expires: Option<String>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryString {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostData {
    pub mime_type: String,
    // this should not be optional,
    // a leniency given because of Chrome.
    pub params: Option<Vec<Param>>,
    pub text: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Param {
    pub name: String,
    pub value: Option<String>,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub size: i64,
    pub compression: Option<i64>,
    // mime type should not be optional, this
    // is a leniancy given because of Firefox.
    pub mime_type: Option<String>,
    pub text: Option<String>,
    pub encoding: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cache {
    pub before_request: Option<CacheEntry>,
    pub after_request: Option<CacheEntry>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    pub expires: Option<String>,
    pub last_access: String,
    pub e_tag: String,
    pub hit_count: u32,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timing {
    pub blocked: Option<f64>,
    pub dns: Option<f64>,
    pub connect: Option<f64>,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    pub ssl: Option<f64>,
    pub comment: Option<String>,
}


fn deserialize_empty_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;
    
    // check for empty object
    if let Value::Object(o) = &value {
        if o.is_empty() {
            return Ok(None);
        }
    }
    
    // convert remaining cases to deserializer and parse
    T::deserialize(value.into_deserializer())
        .map(Some)
        .map_err(|e| serde::de::Error::custom(format!("Failed to deserialize: {}", e)))
}
