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
-include("../src/erlcloud_aws.hrl").
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

%% 2015-01-27 00:00:00 = 1422316800 = ?MIDNIGHT
-define(MIDNIGHT, 1422316800).
-define(DAY, 86400).
-define(HOUR, 3600).

expiration_time_test_() ->
    Tests = [
             %% {TTLSecs, IntervalSecs, MockedTimestamp, ExpectedExpiry}
             {{3600, 900}, {{2015,1,27},{0,0,0}}  , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,0,10}} , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,1,0}}  , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,1,10}} , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,3,0}}  , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,3,30}} , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,5,0}}  , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,10,0}} , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,14,0}} , (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,14,59}}, (?MIDNIGHT + ?HOUR + 900)},
             {{3600, 900}, {{2015,1,27},{0,15,0}} , (?MIDNIGHT + ?HOUR + 1800)},
             {{3600, 900}, {{2015,1,27},{0,15,1}} , (?MIDNIGHT + ?HOUR + 1800)},
             {{3600, 900}, {{2015,1,27},{0,29,59}}, (?MIDNIGHT + ?HOUR + 1800)},
             {{3600, 900}, {{2015,1,27},{0,30,0}} , (?MIDNIGHT + ?HOUR + 2700)},
             {{3600, 900}, {{2015,1,27},{0,44,59}}, (?MIDNIGHT + ?HOUR + 2700)},
             {{3600, 900}, {{2015,1,27},{0,45,0}} , (?MIDNIGHT + ?HOUR + 3600)},
             {{3600, 900}, {{2015,1,27},{0,59,59}}, (?MIDNIGHT + ?HOUR + 3600)},
             {{3600, 900}, {{2015,1,27},{1,0,0}}  , (?MIDNIGHT + ?HOUR + 4500)},

             %% There are 86400 seconds in a day. What happens if the interval is not evenly
             %% divisible in that time? Take 7m for example. 420 secs goes into a day 205.71
             %% times which is a remainder of 300 seconds. We should make sure that we
             %% restart the intervals at midnight, so we don't have day to day drift

             {{3600, 420}, {{2015,1,27},{23,59,0}} , (?MIDNIGHT + ?DAY + ?HOUR)},
             {{3600, 420}, {{2015,1,28},{0,0,0}}   , (?MIDNIGHT + ?DAY + ?HOUR + 420)},

             %% Let's test the old functionality too
             {3600, {{2015,1,27},{0,0,0}} , (?MIDNIGHT + ?HOUR)},
             {3600, {{2015,1,27},{0,0,1}} , (?MIDNIGHT + ?HOUR + 1)},
             {3600, {{2015,1,27},{0,1,1}} , (?MIDNIGHT + ?HOUR + 61)},
             {3600, {{2015,1,28},{0,1,1}} , (?MIDNIGHT + ?DAY + ?HOUR + 61)}
            ],

    TestFun = fun(Arg, MockedTime) ->
                      meck:new(mini_s3, [unstick, passthrough]),
                      meck:expect(mini_s3, universaltime, fun() -> MockedTime end),
                      Expiry = mini_s3:expiration_time(Arg),
                      meck:unload(mini_s3),
                      Expiry
              end,
    [ ?_assertEqual(Expect, TestFun(Arg, MockedTimestamp))
      || {Arg, MockedTimestamp, Expect} <- Tests].

s3_uri_test_() ->
    Config = #config{
               access_key_id = "access_key_id",
               secret_access_key = "secret_access_key"
               },

    RawHeaders = [],

    TestFun = fun({Method, BucketName, Key, Lifetime, MockedTime}) ->
                      meck:new(mini_s3, [no_link, passthrough]),
                      meck:expect(mini_s3, universaltime, fun() -> MockedTime end),
                      meck:expect(mini_s3, make_signed_url_authorization, fun(_,_,_,_,_) -> {"", <<"k6E/2haoGH5vGU9qDTBRs1qNGKA=">>} end),

                      URL = binary_to_list(mini_s3:s3_url(Method, BucketName, Key, Lifetime, RawHeaders, Config)),
                      io:format("URL: ~p~n", [URL]),
                      io:format("History: ~p~n", [meck:history(mini_s3)]),
                      meck:unload(mini_s3),

                      URL
              end,

    Tests = [
             {{'GET', "BUCKET", "KEY", 3600, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET/KEY?AWSAccessKeyId=access_key_id&Expires=1422320400&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"},
             {{'GET', "BUCKET2", "KEY2", {3600, 900}, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET2/KEY2?AWSAccessKeyId=access_key_id&Expires=1422321300&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"}
            ],

    [ ?_assertEqual(Expect, TestFun(Args)) || {Args, Expect} <- Tests].

new_test() ->
    % scheme://host:port
    Config0 = mini_s3:new("key", "secret", "http://host:80"),
    "http://" = Config0#aws_config.s3_scheme,
    80 =  Config0#aws_config.s3_port,

    Config1 = mini_s3:new("key", "secret", "https://host:80"),
    "https://" = Config1#aws_config.s3_scheme,
    80 =  Config1#aws_config.s3_port,

    Config2 = mini_s3:new("key", "secret", "http://host:443"),
    "http://" = Config2#aws_config.s3_scheme,
    443 = Config2#aws_config.s3_port,

    Config3 = mini_s3:new("key", "secret", "https://host:443"),
    "https://" = Config3#aws_config.s3_scheme,
    443 = Config3#aws_config.s3_port, 

    Config4 = mini_s3:new("key", "secret", "https://host:23"),
    "https://" = Config4#aws_config.s3_scheme,
    23 =  Config4#aws_config.s3_port,

    Config5 = mini_s3:new("key", "secret", "http://host:23"),
    "http://" = Config5#aws_config.s3_scheme,
    23 = Config5#aws_config.s3_port,


    % scheme://host
    Config6 = mini_s3:new("key", "secret", "https://host"),
    "https://" = Config6#aws_config.s3_scheme,
    443 = Config6#aws_config.s3_port,

    Config7 = mini_s3:new("key", "secret", "http://host"),
    "http://" = Config7#aws_config.s3_scheme,
    80 = Config7#aws_config.s3_port,


    % host:port
    Config8 = mini_s3:new("key", "secret", "host:80"),
    "http://" = Config8#aws_config.s3_scheme,
    80 = Config8#aws_config.s3_port,

    Config9 = mini_s3:new("key", "secret", "host:443"),
    "https://" = Config9#aws_config.s3_scheme,
    443 = Config9#aws_config.s3_port,

    % this should fail - no scheme to assume
    % or, could just assume https
    %ConfigA = mini_s3:new("key", "secret", "host:23"),
    %f(),


    % host
    ConfigB = mini_s3:new("key", "secret", "host"),
    "https://" = ConfigB#aws_config.s3_scheme,
    443 = ConfigB#aws_config.s3_port.
