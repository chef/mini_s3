-record(config, {
    s3_host="s3.amazonaws.com"::string(),
    access_key_id::string(),
    secret_access_key::string()
}).
-type(config() :: #config{}).

