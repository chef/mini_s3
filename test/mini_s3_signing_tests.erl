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
-module(mini_s3_signing_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../src/internal.hrl").

-define(T, mini_s3_signing).

-define(TEST_TIME, {{2015,8,30},{12,15,19}}).

tapply(Fun, Args) ->
    erlang:apply(?T, Fun, Args).

flat_tapply(Fun, Args) ->
    lists:flatten(erlang:apply(?T, Fun, Args)).

hex_tapply(Fun, Args) ->
     ?T:hexencode((erlang:apply(?T, Fun, Args))).

safe_join_test_() ->
    Tests = [
             {[], [] },
             {["a"], ["a"] },
             {["a", "$", "b"], ["a","b"] },
             {["a", "$", "b", "$", "c"], ["a","b","c"] }
            ],
    [ ?_assertEqual(Expect, ?T:safe_join("$", Input)) || {Expect, Input} <- Tests ].

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
                      meck:new(?T, [unstick, passthrough]),
                      meck:expect(?T, universaltime, fun() -> MockedTime end),
                      Expiry = ?T:expiration_time(Arg),
                      meck:unload(?T),
                      Expiry
              end,
    [ ?_assertEqual(Expect, TestFun(Arg, MockedTimestamp))
      || {Arg, MockedTimestamp, Expect} <- Tests].

make_aws_datetime_test_() ->
    Vec = [{ "20150830T121519Z", [ {{2015,8,30},{12,15,19}} ] },
           { "20150803T011519Z", [ {{2015,8,03},{01,15,19}} ] },
           { "20151212T120519Z", [ {{2015,12,12},{12,5,19}} ] },
           { "20151212T120501Z", [ {{2015,12,12},{12,5,1}} ] }
          ],
    [ ?_assertEqual(E, flat_tapply(make_aws_datetime, A)) || {E,A} <- Vec].

make_aws_date_test_() ->
    Vec = [{ "20150830", [ {{2015,8,30},{12,15,19}} ] },
           { "20150803", [ {{2015,8,03},{12,15,19}} ] },
           { "20151212", [ {{2015,12,12},{12,15,19}} ] }
          ],
    [ ?_assertEqual(E, flat_tapply(make_aws_date, A)) || {E,A} <- Vec].


aws_v4_hash_payload_test_() ->
    Vec = [{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [""] },
           { "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63", [get_fixture_by_name_s("aws/get-vanilla.creq")] }
          ],

    [ ?_assertEqual(E, tapply(aws_v4_hash_payload, A)) || {E,A} <- Vec].

aws_v4_signing_key_test_() ->
    Vec = [{ "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
             [?TEST_TIME, #config{secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region="us-east-1", service = "iam"}] }
          ],

    [ ?_assertEqual(E, hex_tapply(aws_v4_signing_key, A)) || {E,A} <- Vec].


aws_v4_signature_test_() ->
    Vec = [{ "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
             [make_test_key(), make_example_string_to_sign()] }
          ],

    [ ?_assertEqual(E, tapply(aws_v4_signature, A)) || {E,A} <- Vec].


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
    [ ?_assertEqual(Expect, ?T:format_s3_uri(Config(Url, Type), "bucket"))
      || {Url, Type, Expect} <- Tests ].



make_v4_canonical_request_test_() ->
    Vec = [{get_fixture_by_name_s("aws/get-vanilla.creq"),
            [get, "/", "", {{{2015,08,30},{12,36,00}}, 0}, [{"host", "example.amazonaws.com"},{"x-amz-date","20150830T123600Z"}],
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             #config{region = "us-east-1", signing_version = v4}]}
          ],
    [ ?_assertEqual(E,flat_tapply(make_v4_canonical_request, A)) || {E,A} <- Vec].

make_v4_string_to_sign_test_() ->
    Vec = [{get_fixture_by_name_s("aws/get-vanilla.sts"),
            [{ {{2015,08,30},{12,36,00}}, 0},
             ?T:aws_v4_hash_payload(get_fixture_by_name_s("aws/get-vanilla.creq")),
             #config{region = "us-east-1", service="service", signing_version = v4}]},
           {"AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04",
            [ {{{2013,5,24},{0,0,0}}, 86400},
            "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04",
            #config{access_key_id="AKIAIOSFODNN7EXAMPLE",secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    region="us-east-1", service="s3", signing_version = v4}]}
          ],
    [ ?_assertEqual(E,flat_tapply(make_v4_string_to_sign, A)) || {E,A} <- Vec].


make_v4_credential_scope_test_() ->
    Vec = [{"20150830/us-east-1/iam/aws4_request", [?TEST_TIME, #config{region="us-east-1", service="iam", signing_version = v4}] },
           {"20150830/us-east-1/service/aws4_request", [?TEST_TIME, #config{region="us-east-1", service="service", signing_version = v4}] }
          ],
    [ ?_assertEqual(E,flat_tapply(make_v4_credential_scope, A)) || {E,A} <- Vec].

make_signed_url_authorization_v4_test_() ->
    Vec = [{"/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
            [get, "/test.txt", {{{2013,5,24},{0,0,0}}, 86400}, [{host, "examplebucket.s3.amazonaws.com"}],
                 #config{access_key_id="AKIAIOSFODNN7EXAMPLE",secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                         region="us-east-1", service="s3", signing_version = v4}]}
          ],
    [ ?_assertEqual(E,flat_tapply(make_signed_url_authorization_v4, A)) || {E,A} <- Vec].

%%
%%
s3_uri_v2_test_() ->
    Config = #config{
                access_key_id = "access_key_id",
                secret_access_key = "secret_access_key",
                signing_version=v2
               },

    RawHeaders = [],

    TestFun = fun({Method, BucketName, Key, Lifetime, MockedTime}) ->
                      meck:new(mini_s3_signing, [no_link, passthrough]),

                      meck:expect(mini_s3_signing, universaltime, fun() -> MockedTime end),
                      meck:expect(mini_s3_signing, make_signed_url_authorization_v2, fun(_,_,_,_,_) -> {"", <<"k6E/2haoGH5vGU9qDTBRs1qNGKA=">>} end),

                      URL = binary_to_list(mini_s3_signing:s3_url(Method, BucketName, Key, Lifetime, RawHeaders, Config)),
                      io:format("URL: ~p~n", [URL]),
                      io:format("History: ~p~n", [meck:history(mini_s3_signing)]),

                      meck:unload(mini_s3_signing),

                      URL
              end,

    Tests = [
             {{'GET', "BUCKET", "KEY", 3600, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET/KEY?AWSAccessKeyId=access_key_id&Expires=1422320400&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"},
             {{'GET', "BUCKET2", "KEY2", {3600, 900}, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET2/KEY2?AWSAccessKeyId=access_key_id&Expires=1422321300&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"}
            ],

    [ ?_assertEqual(Expect, TestFun(Args)) || {Args, Expect} <- Tests].


s3_uri_v4_test_() ->
    Config = #config{
                access_key_id = "access_key_id",
                secret_access_key = "secret_access_key",
                signing_version=v2
               },

    RawHeaders = [],

    TestFun = fun({Method, BucketName, Key, Lifetime, MockedTime}) ->
                      meck:new(mini_s3_signing, [no_link, passthrough]),

                      meck:expect(mini_s3_signing, universaltime, fun() -> MockedTime end),
                      meck:expect(mini_s3_signing, make_signed_url_authorization_v4, fun(_,_,_,_,_) -> {"", <<"k6E/2haoGH5vGU9qDTBRs1qNGKA=">>} end),

                      URL = binary_to_list(mini_s3_signing:s3_url(Method, BucketName, Key, Lifetime, RawHeaders, Config)),
                      io:format("URL: ~p~n", [URL]),
                      io:format("History: ~p~n", [meck:history(mini_s3_signing)]),

                      meck:unload(mini_s3_signing),

                      URL
              end,

    Tests = [
% TODO FIX
%             {{'GET', "BUCKET", "KEY", 3600, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET/KEY?AWSAccessKeyId=access_key_id&Expires=1422320400&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"},
%             {{'GET', "BUCKET2", "KEY2", {3600, 900}, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET2/KEY2?AWSAccessKeyId=access_key_id&Expires=1422321300&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"}
            ],

    [ ?_assertEqual(Expect, TestFun(Args)) || {Args, Expect} <- Tests].


s3_request_test_() ->
    Config = #config{
                access_key_id = "access_key_id",
                secret_access_key = "secret_access_key",
                signing_version=v2
               },

    RawHeaders = [],

    TestFun = fun({Method, BucketName, Key, Lifetime, MockedTime}) ->
                      meck:new(mini_s3_signing, [no_link, passthrough]),

                      meck:expect(mini_s3_signing, universaltime, fun() -> MockedTime end),
                      meck:expect(mini_s3_signing, make_signed_url_authorization_v4, fun(_,_,_,_,_) -> {"", <<"k6E/2haoGH5vGU9qDTBRs1qNGKA=">>} end),

                      URL = binary_to_list(mini_s3_signing:s3_url(Method, BucketName, Key, Lifetime, RawHeaders, Config)),
                      io:format("URL: ~p~n", [URL]),
                      io:format("History: ~p~n", [meck:history(mini_s3_signing)]),

                      meck:unload(mini_s3_signing),

                      URL
              end,

    Tests = [
             {{'GET', "BUCKET", "KEY", 3600, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET/KEY?AWSAccessKeyId=access_key_id&Expires=1422320400&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"},
             {{'GET', "BUCKET2", "KEY2", {3600, 900}, {{2015,1,27},{0,0,0}}}, "http://s3.amazonaws.com:80/BUCKET2/KEY2?AWSAccessKeyId=access_key_id&Expires=1422321300&Signature=k6E/2haoGH5vGU9qDTBRs1qNGKA%3D"}
            ],

    [ ?_assertEqual(Expect, TestFun(Args)) || {Args, Expect} <- Tests].




%%
%% Support infrastructure
%%
make_test_key() ->
    ?T:aws_v4_signing_key(?TEST_TIME, #config{secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region="us-east-1", service="iam"}).

make_example_string_to_sign() ->
    "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59".


get_fixture_by_name_s(Name) ->
    binary_to_list(get_fixture_by_name_b(Name)).

get_fixture_by_name_b(Name) ->
    Base = code:which(?MODULE),
    DirName = filename:dirname(Base),
    FileName = filename:join([DirName,"fixtures",Name]),
    {ok, File} = file:read_file(FileName),
    File.
