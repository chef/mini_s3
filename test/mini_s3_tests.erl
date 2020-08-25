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
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include("../src/internal.hrl").

-spec format_s3_uri(aws_config(), string()) -> string().
format_s3_uri(Config, Bucket) ->
    erlcloud_s3:get_object_url(Bucket, "", Config).

format_s3_uri_test_() ->
    Config = fun(Url, Type) ->
                     mini_s3:new("", "", Url, Type)
             end,
    Tests = [
             %% hostname
             {"https://my-aws.me.com", vhost, "https://bucket.my-aws.me.com:443/"},
             {"https://my-aws.me.com", path,  "https://my-aws.me.com:443/bucket/"},

             %% ipv4
             {"https://192.168.12.13", path,  "https://192.168.12.13:443/bucket/"},

             %% ipv6
             {"https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]", path,
              "https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:443/bucket/"},

             %% These tests document current behavior. Using
             %% vhost with an IP address does not make sense,
             %% but leaving as-is for now to avoid adding the
             %% is_it_an_ip_or_a_name code.
             {"https://192.168.12.13", vhost, "https://bucket.192.168.12.13:443/"},

             {"https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]", vhost,
              "https://bucket.[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:443/"}
            ],
    [ ?_assertEqual(Expect, format_s3_uri(Config(Url, Type), "bucket"))
      || {Url, Type, Expect} <- Tests ].

% this should be named make_expire_win_test(), but timeout doesn't work unless it's named main_test_()
main_test_() ->
    {timeout, 60,
        fun() ->
                % 10 expiration windows of size 1sec created 1sec apart should be 10 unique windows (i.e. no duplicates)
                Set1 = [{timer:sleep(1000), mini_s3:make_expire_win(0, 1)} || _ <- [1,2,3,4,5,6,7,8,9,0]],
                10   = length(sets:to_list(sets:from_list(Set1))),

                % 100 expiration windows of large size created quickly should be mostly duplicates
                Set2 = [mini_s3:make_expire_win(0, 1000) || _ <- lists:duplicate(100, 0)],
                2   >= length(sets:to_list(sets:from_list(Set2)))
        end
    }.
    
make_expire_win_test() ->
    % lifetime >= ttl
    % lifetime >= expire_win_size
    {_,    1} = mini_s3:make_expire_win(0,       1),
    {_,    1} = mini_s3:make_expire_win(1,       1),
    {_,    2} = mini_s3:make_expire_win(2,       1),
    {_,  100} = mini_s3:make_expire_win(0,     100),
    {_,  100} = mini_s3:make_expire_win(99,    100),
    {_,  100} = mini_s3:make_expire_win(100,   100),
    {_,   L0} = mini_s3:make_expire_win(101,   100),
    true = L0 >= 101,
    {_, 1000} = mini_s3:make_expire_win(0,    1000),
    {_, 1000} = mini_s3:make_expire_win(999,  1000),
    {_, 1000} = mini_s3:make_expire_win(1000, 1000),
    {_,   L1} = mini_s3:make_expire_win(1001, 1000),
    true = L1 >= 1001.

new_test() ->
    % scheme://host:port
    Config0 = mini_s3:new("key", "secret", "http://host:80"),
    "http://" = Config0#aws_config.s3_scheme,
    "host"    = Config0#aws_config.s3_host,
    80        = Config0#aws_config.s3_port,

    Config1 = mini_s3:new("key", "secret", "https://host:80"),
    "https://" = Config1#aws_config.s3_scheme,
    "host"     = Config1#aws_config.s3_host,
    80         = Config1#aws_config.s3_port,

    Config2 = mini_s3:new("key", "secret", "http://host:443"),
    "http://" = Config2#aws_config.s3_scheme,
    "host"    = Config2#aws_config.s3_host,
    443       = Config2#aws_config.s3_port,

    Config3 = mini_s3:new("key", "secret", "https://host:443"),
    "https://" = Config3#aws_config.s3_scheme,
    "host"     = Config3#aws_config.s3_host,
    443        = Config3#aws_config.s3_port, 

    Config4 = mini_s3:new("key", "secret", "https://host:23"),
    "https://" = Config4#aws_config.s3_scheme,
    "host"     = Config4#aws_config.s3_host,
    23         = Config4#aws_config.s3_port,

    Config5 = mini_s3:new("key", "secret", "http://host:23"),
    "http://" = Config5#aws_config.s3_scheme,
    "host"    = Config5#aws_config.s3_host,
    23        = Config5#aws_config.s3_port,

    Config00 = mini_s3:new("key", "secret", "http://[1234:1234:1234:1234:1234:1234:1234:1234]:80"),
    "http://" = Config00#aws_config.s3_scheme,
    "[1234:1234:1234:1234:1234:1234:1234:1234]" = Config00#aws_config.s3_host,
    80 = Config00#aws_config.s3_port,


    % scheme://host
    Config6 = mini_s3:new("key", "secret", "https://host"),
    "https://" = Config6#aws_config.s3_scheme,
    "host"     = Config6#aws_config.s3_host,
    443        = Config6#aws_config.s3_port,

    Config7 = mini_s3:new("key", "secret", "http://host"),
    "http://" = Config7#aws_config.s3_scheme,
    "host"    = Config7#aws_config.s3_host,
    80        = Config7#aws_config.s3_port,

    Config11 = mini_s3:new("key", "secret", "http://[1234:1234:1234:1234:1234:1234:1234:1234]"),
    "http://" = Config11#aws_config.s3_scheme,
    "[1234:1234:1234:1234:1234:1234:1234:1234]" = Config11#aws_config.s3_host,
    80 = Config11#aws_config.s3_port,


    % host:port
    Config8 = mini_s3:new("key", "secret", "host:80"),
    "http://" = Config8#aws_config.s3_scheme,
    "host"    = Config8#aws_config.s3_host,
    80        = Config8#aws_config.s3_port,

    Config9 = mini_s3:new("key", "secret", "host:443"),
    "https://" = Config9#aws_config.s3_scheme,
    "host"     = Config9#aws_config.s3_host,
    443        = Config9#aws_config.s3_port,

    ConfigA = mini_s3:new("key", "secret", "host:23"),
    "https://" = ConfigA#aws_config.s3_scheme,
    "host"     = ConfigA#aws_config.s3_host,
    23         = ConfigA#aws_config.s3_port,

    Config88 = mini_s3:new("key", "secret", "[1234:1234:1234:1234:1234:1234:1234:1234]:80"),
    "http://" = Config88#aws_config.s3_scheme,
    "[1234:1234:1234:1234:1234:1234:1234:1234]" = Config88#aws_config.s3_host,
    80 = Config88#aws_config.s3_port,


    % host
    ConfigB = mini_s3:new("key", "secret", "host"),
    "https://" = ConfigB#aws_config.s3_scheme,
    "host"     = ConfigB#aws_config.s3_host,
    443        = ConfigB#aws_config.s3_port,

    ConfigBB = mini_s3:new("key", "secret", "[1234:1234:1234:1234:1234:1234:1234:1234]"),
    "https://" = ConfigBB#aws_config.s3_scheme,
    "[1234:1234:1234:1234:1234:1234:1234:1234]" = ConfigBB#aws_config.s3_host,
    443 = ConfigBB#aws_config.s3_port.


% toggle port on host header (add port or remove it)
get_host_toggleport_test() ->
    Config0 = mini_s3:new("", "", "host"),
    "host:443" = mini_s3:get_host_toggleport("host", Config0),
    Config1 = mini_s3:new("", "", "host:123"),
    "host" = mini_s3:get_host_toggleport("host:123", Config1),
    Config2 = mini_s3:new("", "", "http://host"),
    "http://host:80" = mini_s3:get_host_toggleport("http://host", Config2),
    Config3 = mini_s3:new("", "", "http://host:123"),
    "http://host" = mini_s3:get_host_toggleport("http://host:123", Config3),
    Config4 = mini_s3:new("", "", "https://host:123"),
    "https://host" = mini_s3:get_host_toggleport("https://host:123", Config4).
