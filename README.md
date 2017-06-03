# twitter-for-rust

## Install

### Cargo.tomlに下記を追加します

```
[dependencies.twitter]
git = "https://github.com/hexium310/twitter-for-rust"
```

### もしくはcargo-editを使用する場合は下記を実行します

```
cargo add twitter --git https://github.com/hexium310/twitter-for-rust

```

## Usage

```
extern crate twitter;
```

### OAuth認証してAccessTokenを取得する場合

```
let mut client = twitter::Client::new(
    Some("Your ConsumerKey".to_string()),
    Some("Your ConsumerSecret".to_string())
)

let request_url = client.get_request_url();

//  Open request_url and get PIN code.

let pin: &str = PIN CODE;
client.set_access_token(pin);
```

### すでにあるAccessTokenを使う場合

```
let mut client = twitter::Client {
    consumer_key: Some("Your ConsumerKey".to_string()),
    consumer_secret: Some("Your ConsumerSecret".to_string()),
    access_token: Some("Your AccessToken".to_string()),
    access_token_secret: Some("Your AccessTokenSecret".to_string())
};
```

### 実際に使う場合

```
let mut param = std::collections::BTreeMap::<&str, &str>::new();
param.isnert("status", "Your Tweet");

let json: serde_json::Value = client.post("statuses/update", param);
```
