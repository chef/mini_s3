%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
-record(config, {
          s3_url="http://s3.amazonaws.com"::string(),
          access_key_id::string(),
          secret_access_key::string(),
          bucket_access_type=virtual_hosted::mini_s3:bucket_access_type()

}).
