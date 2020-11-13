%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Amazon Simple Storage Service (S3)
%% Copyright 2010 Brian Buchanan. All Rights Reserved.
%% Copyright 2012 Opscode, Inc. All Rights Reserved.
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

-module(mini_s3).

-export([
         copy_object/5,
         copy_object/6,
         create_bucket/3,
         create_bucket/4,
         delete_bucket/2,
         delete_object/2,
         delete_object/3,
         delete_object_version/3,
         delete_object_version/4,
         get_bucket_attribute/2,
         get_bucket_attribute/3,
         get_object/4,
         get_object_acl/2,
         get_object_acl/3,
         get_object_acl/4,
         get_object_torrent/2,
         get_object_torrent/3,
         get_object_metadata/4,
         list_buckets/1,
         list_objects/2,
         list_objects/3,
         list_object_versions/2,
         list_object_versions/3,
         new/3,
         new/4,
         new/5,
         put_object/6,
         s3_url/6,
         s3_url/7,
         set_bucket_attribute/3,
         set_bucket_attribute/4,
         set_object_acl/3,
         set_object_acl/4
]).

-export([make_authorization/10,
         manual_start/0,
         make_expire_win/2,
         universaltime/0
]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-export([expiration_time/1]).

-type s3_bucket_attribute_name() :: acl
                                  | location
                                  | logging
                                  | request_payment
                                  | versioning
                                  | notification.

-type s3_bucket_acl() :: private
                       | public_read
                       | public_read_write
                       | authenticated_read
                       | bucket_owner_read
                       | bucket_owner_full_control.

-type s3_location_constraint() :: none
                                | us_west_1
                                | eu
                                | 'us-east-1'
                                | 'us-east-2'
                                | 'us-west-1'
                                | 'us-west-2'
                                | 'ca-central-1'
                                | 'eu-west-1'
                                | 'eu-west-2'
                                | 'eu-west-3'
                                | 'eu-north-1'
                                | 'eu-central-1'
                                | 'ap-south-1'
                                | 'ap-southeast-1'
                                | 'ap-southeast-2'
                                | 'ap-northeast-1'
                                | 'ap-northeast-2'
                                | 'ap-northeast-3'
                                | 'ap-east-1'
                                | 'me-south-1'
                                | 'sa-east-1'.

-export_type([aws_config/0,
              s3_bucket_attribute_name/0,
              s3_bucket_acl/0,
              s3_location_constraint/0]).

-type bucket_access_type() :: vhost | path.

%% This is a helper function that exists to make development just a
%% wee bit easier
-spec manual_start() -> ok.
manual_start() ->
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),
    application:start(inets).

-spec discern_ipv(string()) -> pos_integer().
discern_ipv(Url) ->
    case lists:member($[, Url) andalso lists:member($], Url) of
        true  -> 6;
        false -> 4
    end.

-spec new(string() | binary(), string() | binary(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Url) ->
    Ipv     = discern_ipv(Url),

    Parse   =
        case {Ipv, Url} of
            % uri_string:parse won't parse ipv6 with missing scheme. detect and fix.
            {6, [$[ | _]} -> uri_string:parse(["no-scheme://", Url]);
            _             -> uri_string:parse(                 Url )
        end,

    Path0   = maps:get(path  , Parse           ),
    Host0   = maps:get(host  , Parse, undefined),
    Scheme0 = maps:get(scheme, Parse, undefined),
    Port0   = maps:get(port  , Parse, undefined),

    % uri_string:parse parses URLs shaped as "host" or "host:port" incorrectly, e.g.:
    %
    %   % should be #{host => "host"}
    %   > uri_string:parse("host").
    %   #{path => "host"}
    %
    %   % should be #{host => "host", port => 80}
    %   > uri_string:parse("host:80").
    %   #{path => "80",scheme => "host"}
    %
    % detect and repair any erroneous parse.
    {Scheme1, Host1, Path1, Port1} =
        case {Scheme0, Host0, Path0, Port0} of
            {undefined, undefined, _, undefined} when Path0 /= undefined
                                                 -> {undefined, Path0,   "",    undefined             };
            {_,         undefined, _, undefined} -> {undefined, Scheme0, "",    list_to_integer(Path0)};
             _                                   -> {Scheme0,   Host0,   Path0, Port0                 }
        end,

    Host2   = case Ipv of 4 -> Host1; _ -> "[" ++ Host1 ++ "]" end,

    {Scheme, Port} =
        case {Scheme1, Port1} of
            {undefined,   undefined} -> {"https://",   443};
            {undefined,          80} -> {"http://",     80};
            {undefined,           _} -> {"https://", Port1};
            {"http",      undefined} -> {"http://",     80};
            {"http",              _} -> {"http://",  Port1};
            {"https",     undefined} -> {"https://",   443};
            {"https",             _} -> {"https://", Port1};
            {"no-scheme", undefined} -> {"https://",   443};
            {"no-scheme",        80} -> {"http://",     80};
            {"no-scheme",         _} -> {"https://", Port1};
            _                        -> {Scheme1,    Port1}
        end,

    %% bookshelf wants bucketname after host e.g. https://api.chef-server.dev:443/bookshelf.
    %% s3 wants bucketname before host (actually, it takes it either way) e.g. https://bookshelf.api.chef-server.dev:443.
    %%
    %% UPDATE
    %% amazon: "Buckets created after September 30, 2020, will support only virtual hosted-style requests.
    %% Path-style requests will continue to be supported for buckets created on or before this date."
    %% for further discussion, see:
    %%  https://aws.amazon.com/blogs/aws/amazon-s3-path-deprecation-plan-the-rest-of-the-story/
    %%  https://github.com/chef/chef-server/issues/2088
    %%  https://github.com/chef/chef-server/issues/1911
    (erlcloud_s3:new(AccessKeyID, SecretAccessKey, Host2++Path1, Port))#aws_config{s3_scheme=Scheme, s3_bucket_after_host=true, s3_bucket_access_method=path}.

% old mini_s3:
%   -spec new(string(), string(), string(), bucket_access_type()) -> aws_config().
%   mini_s3:new(accesskey, secretaccesskey, host, bucketaccesstype)
-spec new(string() | binary(), string() | binary(), string(), bucket_access_type()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, BucketAccessType) ->
    {BucketAccessMethod, BucketAfterHost} = case BucketAccessType of path -> {path, true}; _ -> {vhost, false} end,
    Config = new(AccessKeyID, SecretAccessKey, Host),
    Config#aws_config{
        s3_bucket_access_method=BucketAccessMethod,
        s3_bucket_after_host=BucketAfterHost
    }.

% erlcloud has no new/5, and arguments differ.
% for now, attempting conversion to new/4 (dropping SslOpts).
% see: https://github.com/chef/chef-server/issues/2171
-spec new(string() | binary(), string() | binary(), string(), bucket_access_type(), proplists:proplist()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, BucketAccessType, _SslOpts) ->
    new(AccessKeyID, SecretAccessKey, Host, BucketAccessType).

-define(XMLNS_S3, "http://s3.amazonaws.com/doc/2006-03-01/").

-spec copy_object(string(), string(), string(), string(), proplists:proplist()) -> proplists:proplist().
copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options) ->
    erlcloud_s3:copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options).

-spec copy_object(string(), string(), string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, Config) ->
    erlcloud_s3:copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, Config).

-spec create_bucket(string(), s3_bucket_acl(), s3_location_constraint() | aws_config()) -> ok.
create_bucket(BucketName, ACL, LocationConstraint) ->
    erlcloud_s3:create_bucket(BucketName, ACL, LocationConstraint).

-spec create_bucket(string(), s3_bucket_acl(), s3_location_constraint(), aws_config()) -> ok.
create_bucket(BucketName, ACL, LocationConstraint, Config) ->
    erlcloud_s3:create_bucket(BucketName, ACL, LocationConstraint, Config).

-spec delete_bucket(string(), aws_config()) -> ok.
delete_bucket(BucketName, Config) ->
    erlcloud_s3:delete_bucket(BucketName, Config).

-spec delete_object(string(), string()) -> proplists:proplist().
delete_object(BucketName, Key) ->
    erlcloud_s3:delete_object(BucketName, Key).

-spec delete_object(string(), string(), aws_config()) -> proplists:proplist().
delete_object(BucketName, Key, Config) ->
    erlcloud_s3:delete_object(BucketName, Key, Config).

-spec delete_object_version(string(), string(), string()) -> proplists:proplist().
delete_object_version(BucketName, Key, Version) ->
    erlcloud_s3:delete_object_version(BucketName, Key, Version).

-spec delete_object_version(string(), string(), string(), aws_config()) -> proplists:proplist().
delete_object_version(BucketName, Key, Version, Config) ->
    erlcloud_s3:delete_object_version(BucketName, Key, Version, Config).

-spec list_buckets(aws_config()) -> proplists:proplist().
list_buckets(Config) ->
    Result = erlcloud_s3:list_buckets(Config),
    case proplists:lookup(buckets, Result) of none -> [{buckets, []}]; X -> [X] end.

-spec list_objects(string(), proplists:proplist()) -> proplists:proplist().
list_objects(BucketName, Options) ->
    erlcloud_s3:list_objects(BucketName, Options).

-spec list_objects(string(), proplists:proplist(), aws_config()) -> proplists:proplist().
list_objects(BucketName, Options, Config) ->
    List = erlcloud_s3:list_objects(BucketName, Options, Config),
    [{name, Name} | Rest] = List,
    %[{name, http_uri:decode(Name)} | Rest].
    [{name, decode(Name)} | Rest].

-spec get_bucket_attribute(string(), s3_bucket_attribute_name()) -> term().
get_bucket_attribute(BucketName, AttributeName) ->
    erlcloud_s3:get_bucket_attribute(BucketName, AttributeName).

-spec get_bucket_attribute(string(), s3_bucket_attribute_name(), aws_config()) -> term().
get_bucket_attribute(BucketName, AttributeName, Config) ->
    erlcloud_s3:get_bucket_attribute(BucketName, AttributeName, Config).

%% Abstraction of universaltime, so it can be mocked via meck
-spec universaltime() -> calendar:datetime().
universaltime() ->
    erlang:universaltime().

-spec if_not_empty(string(), iolist()) -> iolist().
if_not_empty("", _V) ->
    "";
if_not_empty(_, Value) ->
    Value.

-spec s3_url(atom(), string(), string(), non_neg_integer() | {non_neg_integer(), non_neg_integer()}, proplists:proplist(), aws_config()) -> binary().
s3_url(Method, BucketName0, Key0, {TTL, ExpireWin}, RawHeaders, Config) ->
    {Date, Lifetime} = make_expire_win(TTL, ExpireWin),
    s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Date, Config);
s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Config)
  when is_list(BucketName0), is_list(Key0), is_tuple(Config) ->
    [BucketName, Key] = [ms3_http:url_encode_loose(X) || X <- [BucketName0, Key0]],
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Config),
    iolist_to_binary(RequestURI).

-spec s3_url(atom(), string(), string(), non_neg_integer(), proplists:proplist(), string(), aws_config()) -> binary().
s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Date, Config)
  when is_list(BucketName0), is_list(Key0), is_tuple(Config) ->
    [BucketName, Key] = [ms3_http:url_encode_loose(X) || X <- [BucketName0, Key0]],
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Date, Config),
    iolist_to_binary(RequestURI).

%-----------------------------------------------------------------------------------
% Implementation of expiration windows for sigv4, for making batches
% of cacheable presigned URLs.
%
%          past       present      future
%                        |
% ------+------+------+--+---+------+------+------+------
%       |      |      |  |   |      |      |      | time
% ------+------+------+--+---+------+------+------+------
%                     |    ^ |
%      x-amz-date ----+    | +---- x-amz-expires
%                        |-|
%                        TTL
%                     |------|
%                     Lifetime
%
% Given a TTL, x-amz-expires should be set to be the closest expiry-window
% boundary >= present+TTL, ie present+TTL selects the expiry-window. Squelch
% any resulting Lifetime of greater than one week to one week.
%
% 1) Segment all of time into 'windows' of width expiry-window-size.
% 2) Align x-amz-date to nearest expiry-window boundary less than present time.
% 3) Align x-amz-expires to nearest expiry-window boundary greater than present time.
% 4) The right edge of present+TTL is a 'selector' to determine which expiration
%    window we are in, thus determining final value of x-amz-expires and Lifetime.
% 5) While x-amz-expires - present < TTL, x-amz-expires += expiry-window-size.
% 6) Lifetime = x-amz-expires - x-amz-date, or WEEKSEC, whichever is less.
%-----------------------------------------------------------------------------------
-define(WEEKSEC, 604800).
-spec make_expire_win(non_neg_integer(), non_neg_integer()) -> {string(), non_neg_integer()}.
make_expire_win(TTL, ExpireWinSiz) when ExpireWinSiz > 0 ->
    Present = calendar:datetime_to_gregorian_seconds(calendar:now_to_universal_time(os:timestamp())),
    XAmzDateSec = Present div ExpireWinSiz * ExpireWinSiz,
    ExpirWinMult = ((TTL div ExpireWinSiz) + (case TTL rem ExpireWinSiz > 0 of true -> 1; _ -> 0 end)),
    XAmzExpires = case ExpirWinMult of 0 -> 1; _ -> ExpirWinMult end * ExpireWinSiz + XAmzDateSec,
    Lifetime =
        case (L = XAmzExpires - XAmzDateSec) > ?WEEKSEC of
            true -> ?WEEKSEC;
            _    -> L
        end,
    {erlcloud_aws:iso_8601_basic_time(calendar:gregorian_seconds_to_datetime(XAmzDateSec)), Lifetime}.

%-----------------------------------------------------------------------------------------
%% calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}).
-define(EPOCH, 62167219200).
-define(DAY, 86400).

%% @doc Number of seconds since the Epoch that a request can be valid for, specified by
%% TimeToLive, which is the number of seconds from "right now" that a request should be
%% valid. If the argument provided is a tuple, we use the interval logic that will only
%% result in Interval / 86400 unique expiration times per day
-spec expiration_time(TimeToLive :: non_neg_integer() | {non_neg_integer(), non_neg_integer()}) ->
                             Expires::non_neg_integer().
expiration_time({TimeToLive, Interval}) ->
    {{NowY, NowMo, NowD},{_,_,_}} = Now = mini_s3:universaltime(),
    NowSecs = calendar:datetime_to_gregorian_seconds(Now),
    MidnightSecs = calendar:datetime_to_gregorian_seconds({{NowY, NowMo, NowD},{0,0,0}}),
    %% How many seconds are we into today?
    TodayOffset = NowSecs - MidnightSecs,
    Buffer = case (TodayOffset + Interval) >= ?DAY of
        %% true if we're in the day's last interval, don't let it spill into tomorrow
        true ->
            ?DAY - TodayOffset;
        %% false means this interval is bounded by today
        _ ->
            Interval - (TodayOffset rem Interval)
    end,
    NowSecs + Buffer - ?EPOCH + TimeToLive;
expiration_time(TimeToLive) ->
    Now = calendar:datetime_to_gregorian_seconds(mini_s3:universaltime()),
    (Now - ?EPOCH) + TimeToLive.

%-----------------------------------------------------------------------------------------

-spec get_object(string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
get_object(BucketName, Key, Options, Config) ->
    erlcloud_s3:get_object(BucketName, Key, Options, Config).

-spec get_object_acl(string(), string()) -> proplists:proplist().
get_object_acl(BucketName, Key) ->
    erlcloud_s3:get_object_acl(BucketName, Key).

-spec get_object_acl(string(), string(), proplists:proplist() | aws_config()) -> proplists:proplist().
get_object_acl(BucketName, Key, Config) ->
    erlcloud_s3:get_object_acl(BucketName, Key, Config).

-spec get_object_acl(string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
get_object_acl(BucketName, Key, Options, Config) ->
    erlcloud_s3:get_object_acl(BucketName, Key, Options, Config).

-spec get_object_metadata(string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
get_object_metadata(BucketName, Key, Options, Config) ->
    erlcloud_s3:get_object_metadata(BucketName, Key, Options, Config).

-spec get_object_torrent(string(), string()) -> proplists:proplist().
get_object_torrent(BucketName, Key) ->
    erlcloud_s3:get_object_torrent(BucketName, Key).

-spec get_object_torrent(string(), string(), aws_config()) -> proplists:proplist().
get_object_torrent(BucketName, Key, Config) ->
    erlcloud_s3:get_object_torrent(BucketName, Key, Config).

-spec list_object_versions(string(), proplists:proplist() | aws_config()) -> proplists:proplist().
list_object_versions(BucketName, Options) ->
    erlcloud_s3:list_object_versions(BucketName, Options).

-spec list_object_versions(string(), proplists:proplist(), aws_config()) -> proplists:proplist().
list_object_versions(BucketName, Options, Config) ->
    erlcloud_s3:list_object_versions(BucketName, Options, Config).

-spec put_object(string(), string(), iodata(), proplists:proplist(), [{string(), string()}],  aws_config()) -> proplists:proplist().
put_object(BucketName, Key, Value, Options, HTTPHeaders, Config) ->
    erlcloud_s3:put_object(BucketName, Key, Value, Options, HTTPHeaders, Config).

-spec set_object_acl(string(), string(), proplists:proplist()) -> ok.
set_object_acl(BucketName, Key, ACL) ->
    erlcloud_s3:set_object_acl(BucketName, Key, ACL).

-spec set_object_acl(string(), string(), proplists:proplist(), aws_config()) -> ok.
set_object_acl(BucketName, Key, ACL, Config) ->
    erlcloud_s3:set_object_acl(BucketName, Key, ACL, Config).

-spec set_bucket_attribute(string(), atom(), term()) -> ok.
set_bucket_attribute(BucketName, AttributeName, Value) ->
    erlcloud_s3:set_bucket_attribute(BucketName, AttributeName, Value).

-spec set_bucket_attribute(string(), atom(), term(), aws_config()) -> ok.
set_bucket_attribute(BucketName, AttributeName, Value, Config) ->
    erlcloud_s3:set_bucket_attribute(BucketName, AttributeName, Value, Config).

make_authorization(AccessKeyId, SecretKey, Method, ContentMD5, ContentType, Date, AmzHeaders,
                   Host, Resource, Subresource) ->
    CanonizedAmzHeaders =
        [[Name, $:, Value, $\n] || {Name, Value} <- lists:sort(AmzHeaders)],
    StringToSign = [string:to_upper(atom_to_list(Method)), $\n,
                    ContentMD5, $\n,
                    ContentType, $\n,
                    Date, $\n,
                    CanonizedAmzHeaders,
                    if_not_empty(Host, [$/, Host]),
                    Resource,
                    if_not_empty(Subresource, [$?, Subresource])],
    %Signature = base64:encode(crypto:hmac(sha, SecretKey, StringToSign)),
    Signature = base64:encode(crypto:mac(hmac, sha, SecretKey, StringToSign)),
    {StringToSign, ["AWS ", AccessKeyId, $:, Signature]}.


% ----------------------------------------------------
% local functions
% ----------------------------------------------------

-spec decode(string() | binary()) -> string() | binary().
decode(String) when is_list(String) ->
    do_decode(String);
decode(String) when is_binary(String) ->
    do_decode_binary(String).

do_decode([$%,Hex1,Hex2|Rest]) ->
    [hex2dec(Hex1)*16+hex2dec(Hex2)|do_decode(Rest)];
do_decode([First|Rest]) ->
    [First|do_decode(Rest)];
do_decode([]) ->
    [].

do_decode_binary(<<$%, Hex:2/binary, Rest/bits>>) ->
    <<(binary_to_integer(Hex, 16)), (do_decode_binary(Rest))/binary>>;
do_decode_binary(<<First:1/binary, Rest/bits>>) ->
    <<First/binary, (do_decode_binary(Rest))/binary>>;
do_decode_binary(<<>>) ->
    <<>>.

hex2dec(X) when (X>=$0) andalso (X=<$9) -> X-$0;
hex2dec(X) when (X>=$A) andalso (X=<$F) -> X-$A+10;
hex2dec(X) when (X>=$a) andalso (X=<$f) -> X-$a+10.

% ----------------------------------------------------
% currently unused
% ----------------------------------------------------

%-spec delete_bucket(string()) -> ok.
%delete_bucket(BucketName) ->
%    erlcloud_s3:delete_bucket(BucketName).

%-spec get_object(string(), string(), proplists:proplist()) -> proplists:proplist().
%get_object(BucketName, Key, Options) ->
%    erlcloud_s3:get_object(BucketName, Key, Options).

%-spec put_object(string(), string(), iodata(), proplists:proplist(), [{string(), string()}] | aws_config()) -> proplists:proplist().
%put_object(BucketName, Key, Value, Options, HTTPHeaders) ->
%    erlcloud_s3:put_object(BucketName, Key, Value, Options, HTTPHeaders).

% for some functions which don't pass in Configs
%default_config() ->
%    Defaults =  envy:get(mini_s3, s3_defaults, list),
%    case proplists:is_defined(key_id, Defaults) andalso
%        proplists:is_defined(secret_access_key, Defaults) of
%        true ->
%            {key_id, Key} = proplists:lookup(key_id, Defaults),
%            {secret_access_key, AccessKey} =
%                proplists:lookup(secret_access_key, Defaults),
%            #aws_config{access_key_id=Key, secret_access_key=AccessKey};
%        false ->
%            throw({error, missing_s3_defaults})
%    end.
