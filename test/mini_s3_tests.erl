%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Copyright 2013 Opscode, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
-module(mini_s3_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../src/internal.hrl").

format_s3_uri_test_() ->
    Config = fun(Url, Type) ->
                     #config{s3_url = Url, bucket_access_type = Type}
             end,
    Tests = [
             %% hostname
             {"https://my-aws.me.com", virtual_hosted, "https://bucket.my-aws.me.com:443"},
             {"https://my-aws.me.com", path, "https://my-aws.me.com:443/bucket"},

             %% ipv4
             {"https://192.168.12.13", path, "https://192.168.12.13:443/bucket"},

             %% ipv6
             {"https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]", path,
              "https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:443/bucket"},

             %% These tests document current behavior. Using
             %% virtual_hosted with an IP address does not make sense,
             %% but leaving as-is for now to avoid adding the
             %% is_it_an_ip_or_a_name code.
             {"https://192.168.12.13", virtual_hosted, "https://bucket.192.168.12.13:443"},

             {"https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]", virtual_hosted,
              "https://bucket.[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:443"}
            ],
    [ ?_assertEqual(Expect, mini_s3:format_s3_uri(Config(Url, Type), "bucket"))
      || {Url, Type, Expect} <- Tests ].
