extern crate base64;
extern crate crypto;
extern crate hyper;
extern crate hyper_native_tls;
extern crate rand;
extern crate serde_json;
extern crate time;
extern crate url;

use std::io::Read;
use std::collections::{HashMap, BTreeMap};

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use hyper::Client;
use hyper::header::{Headers, Authorization, ContentType};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use rand::Rng;
use url::Url;
use url::percent_encoding::{EncodeSet, percent_encode};

#[derive(Copy, Clone)]
struct StrictEncodeSet;

impl EncodeSet for StrictEncodeSet {
    fn contains(&self, byte: u8) -> bool {
        !((byte >= "0".as_bytes()[0] && byte <= "9".as_bytes()[0]) ||
            (byte >= "a".as_bytes()[0] && byte <= "z".as_bytes()[0]) ||
            (byte >= "A".as_bytes()[0] && byte <= "Z".as_bytes()[0]) ||
            (byte == "-".as_bytes()[0]) ||
            (byte == ".".as_bytes()[0]) ||
            (byte == "_".as_bytes()[0]) ||
            (byte == "~".as_bytes()[0])
        )
    }
}

#[derive(Clone, Debug)]
pub struct Oauth {
    pub consumer_key: Option<String>,
    pub consumer_secret: Option<String>,
    pub access_token: Option<String>,
    pub access_token_secret: Option<String>
}

impl Oauth {
    pub fn new(ck: Option<String>, cs: Option<String>, at: Option<String>, ats: Option<String>) -> Oauth {
        Oauth {
            consumer_key: ck,
            consumer_secret: cs,
            access_token: at,
            access_token_secret: ats
        }
    }

    pub fn get_request_url(&mut self) -> String {
        let (request_token, request_token_secret) = get_request_token(&self).unwrap();
        let mut request_url = Url::parse("http://api.twitter.com/oauth/authorize").unwrap();
        request_url.query_pairs_mut().append_pair("oauth_token", &request_token);
        request_url.query_pairs_mut().append_pair("oauth_token_secret", &request_token_secret);

        self.access_token = Some(request_token);
        self.access_token_secret = Some(request_token_secret);
        request_url.to_string()
    }

    pub fn set_access_token(&mut self, verifier: &str) {
        let url = "https://api.twitter.com/oauth/access_token";

        let token = self.access_token.clone().unwrap();
        let token_secret = self.access_token_secret.clone().unwrap();

        let mut params: BTreeMap<&str, &str> = BTreeMap::new();
        params.insert("oauth_token", &token);
        params.insert("oauth_verifier", verifier);
        let (header, _) = build_request(&self, "POST", url, params, &token_secret);

        let (oauth_token, oauth_token_secret) = get_oauth_token(get_token(url, &header)).unwrap();
        self.access_token = Some(oauth_token);
        self.access_token_secret = Some(oauth_token_secret);
    }

    pub fn post(&self, endpoint: &str, param: BTreeMap<&str, &str>) -> serde_json::Value {
        let url = format!("https://api.twitter.com/1.1/{}", endpoint);
        let token = self.access_token.clone().unwrap();
        let token_secret = self.access_token_secret.clone().unwrap();

        let mut param = param;
        param.insert("oauth_token", &token);

        let (header, body) = build_request(&self, "POST", &url, param, &token_secret);

        let mut headers = Headers::new();
        headers.set(Authorization(header));
        headers.set(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![(Attr::Charset, Value::Utf8)])));
        let client = Client::with_connector(HttpsConnector::new(NativeTlsClient::new().unwrap()));
        let mut res = client.post(&url)
            .headers(headers)
            .body(&body)
            .send()
            .unwrap();
        let mut response_body = String::new();
        res.read_to_string(&mut response_body).unwrap();

        match serde_json::from_str::<serde_json::Value>(&response_body) {
            Ok(json) => json,
            Err(..) => panic!("Err"),
        }
    }

    pub fn get(&self, endpoint: &str, param: BTreeMap<&str, &str>) -> serde_json::Value {
        let url = format!("https://api.twitter.com/1.1/{}", endpoint);
        let token = self.access_token.clone().unwrap();
        let token_secret = self.access_token_secret.clone().unwrap();

        let mut param = param;
        param.insert("oauth_token", &token);

        let (header, _) = build_request(&self, "GET", &url, param, &token_secret);

        let mut headers = Headers::new();
        headers.set(Authorization(header));
        let client = Client::with_connector(HttpsConnector::new(NativeTlsClient::new().unwrap()));
        let mut res = client.get(&url)
            .headers(headers)
            .send()
            .unwrap();
        let mut response_body = String::new();
        res.read_to_string(&mut response_body).unwrap();

        match serde_json::from_str::<serde_json::Value>(&response_body) {
            Ok(json) => json,
            Err(..) => panic!("Err"),
        }
    }
}

fn encode(s: &str) -> String {
    percent_encode(s.as_bytes(), StrictEncodeSet).collect::<String>()
}

fn build_request(
    oauth: &Oauth,
    method: &str,
    url: &str,
    append_params: BTreeMap<&str, &str>,
    oauth_token_secret: &str
) -> (String, String) {
    let nonce = rand::thread_rng().gen_ascii_chars().take(32).collect::<String>();
    let now_time = time::now().to_timespec().sec.to_string();
    let key = oauth.consumer_key.clone().unwrap();
    let key_secret = oauth.consumer_secret.clone().unwrap();

    let mut params: BTreeMap<&str, &str> = BTreeMap::new();
    params.insert("oauth_consumer_key", &key);
    params.insert("oauth_nonce", &nonce);
    params.insert("oauth_signature_method", "HMAC-SHA1");
    params.insert("oauth_timestamp", &now_time);
    params.insert("oauth_version", "1.0a");

    for (k, v) in append_params {
        params.insert(k, v);
    }

    let param = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let oauth_signature = {
        let signature_param = format!("{}&{}&{}", encode(method.to_uppercase().as_str()), encode(url), encode(&param));
        let key = format!("{}&{}", encode(&key_secret), encode(oauth_token_secret));
        let mut hmac = Hmac::new(Sha1::new(), key.as_bytes());
        hmac.input(signature_param.as_bytes());
        base64::encode(hmac.result().code())
    };

    let mut values = params;
    values.insert("oauth_signature", &oauth_signature);

    (build_header(&values), build_body(&values))
}

fn build_header(params: &BTreeMap<&str, &str>) -> String {
    let header = params
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("OAuth {}", header)
}

fn build_body(params: &BTreeMap<&str, &str>) -> String {
    params
        .iter()
        .filter(|&(k, _)| !k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}={}", k, encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn get_token(url: &str, header_value: &str) -> String {
    let client = Client::with_connector(HttpsConnector::new(NativeTlsClient::new().unwrap()));
    let mut headers = Headers::new();
    headers.set(Authorization(header_value.to_string()));
    let mut res = client
        .post(url)
        .headers(headers)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();

    body
}

fn get_request_token(oauth: &Oauth) -> Result<(String, String), String> {
    let url = "https://api.twitter.com/oauth/request_token";

    let mut params = BTreeMap::new();
    params.insert("oauth_callback", "oob");
    let (header, _) = build_request(&oauth, "POST", url, params, "");

    get_oauth_token(get_token(url, &header))
}

fn get_oauth_token(body: String) -> Result<(String, String), String> {
    let query = match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(json) => return Err(json["errors"][0]["message"].to_string()),
        Err(..) => body,
    };

    let mut parsed_url = Url::parse("http://example.com").unwrap();
    parsed_url.set_query(Some(&query));
    let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

    Ok((hash_query["oauth_token"].to_string(), hash_query["oauth_token_secret"].to_string()))
}
