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

%-behavior(application).

-export([
         new/3,
         new/4,
         new/5,
         create_bucket/3,
         create_bucket/4,
         delete_bucket/1,
         delete_bucket/2,
         get_bucket_attribute/2,
         get_bucket_attribute/3,
         list_buckets/1,
         set_bucket_attribute/3,
         set_bucket_attribute/4,
         list_objects/2,
         list_objects/3,
         list_object_versions/2,
         list_object_versions/3,
         copy_object/5,
         copy_object/6,
         delete_object/2,
         delete_object/3,
         delete_object_version/3,
         delete_object_version/4,
         get_object/3,
         get_object/4,
         get_object_acl/2,
         get_object_acl/3,
         get_object_acl/4,
         get_object_torrent/2,
         get_object_torrent/3,
         get_object_metadata/4,
         get_host_toggleport/2,
         get_url_noport/1,
         get_url_port/1,
         s3_url/6,
         s3_url/7,
         put_object/5,
         put_object/6,
         set_object_acl/3,
         set_object_acl/4]).

-export([manual_start/0,
         make_authorization/10,
         universaltime/0]).

-export([make_expire_win/2]).
-include_lib("eunit/include/eunit.hrl").  % <----- need to delete this
-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
%-include_lib("eunit/include/eunit.hrl"). % <----- and add this
-endif.

% is this used?  TODO: try removing
-include("internal.hrl").
-include_lib("xmerl/include/xmerl.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").


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

-spec new(string() | binary(), string() | binary(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host0) ->
    % chef-server crams scheme://host:port all into into Host; erlcloud wants them separate.
    % Assume:
    %   Host   == scheme://domain:port | scheme://domain | domain:port | domain
    %   scheme == http | https

    % ipv4/6 detection
    {Ipv, Host} =
        case string:tokens(Host0, "[]") of
            [Host0] ->
                % ipv4
                Domain0 = "",
                {4, Host0};
            % ipv6
            [Scheme0,    Domain0, Port0] -> {6, lists:flatten([Scheme0,    $x, Port0])};
            ["http://",  Domain0       ] -> {6, lists:flatten(["http://",  $x       ])};
            ["https://", Domain0       ] -> {6, lists:flatten(["https://", $x       ])};
            [            Domain0, Port0] -> {6, lists:flatten([            $x, Port0])};
            [            Domain0       ] -> {6, "x"}
        end,

    case string:split(Host, ":", all) of
        % Host == scheme://domain:port
        [Scheme1, [$/, $/ | Domain1] | [Port1]] ->
            Scheme = Scheme1 ++ "://";
        % Host == scheme://domain
        [Scheme1, [$/, $/ | Domain1]] ->
            Scheme = Scheme1 ++ "://",
            Port1  = undefined;
        % Host == domain:port
        [Domain1, Port1] ->
            Scheme = case Port1 of "80" -> "http://"; _ -> "https://" end;
        % Host == domain
        [Domain1] ->
            Scheme = "https://",
            Port1  = undefined
    end,
    Port =
        case Port1 of
            undefined ->
                case Scheme of
                    "https://" -> 443;
                    "http://"  -> 80
                end;
            _ ->
                list_to_integer(Port1)
        end,
    Domain = case Ipv of 4 -> Domain1; _ -> "[" ++ Domain0 ++ "]" end,
    %% bookshelf wants bucketname after host e.g. https://api.chef-server.dev:443/bookshelf...
    %% s3 wants bucketname before host (or it takes it either way) e.g. https://bookshelf.api.chef-server.dev:443...
    %% amazon: "Buckets created after September 30, 2020, will support only virtual hosted-style requests. Path-style
    %% requests will continue to be supported for buckets created on or before this date."
    %% for further discussion, see: https://github.com/chef/chef-server/issues/1911
    (erlcloud_s3:new(AccessKeyID, SecretAccessKey, Domain, Port))#aws_config{s3_scheme=Scheme, s3_bucket_after_host=true, s3_bucket_access_method=path}.

% erlcloud wants accesskey, secretaccesskey, host, port.
% mini_s3  wants accesskey, secretaccesskey, host, bucketaccesstype
%-spec new(string(), string(), string(), bucket_access_type()) -> aws_config().
-spec new(string() | binary(), string() | binary(), string(), bucket_access_type()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, BucketAccessType) ->
    % convert mini_s3 new/4 to erlcloud
    {BucketAccessMethod, BucketAfterHost} = case BucketAccessType of path -> {path, true}; _ -> {vhost, false} end,
    Config = new(AccessKeyID, SecretAccessKey, Host),
    Config#aws_config{
        s3_bucket_access_method=BucketAccessMethod,
        s3_bucket_after_host=BucketAfterHost
    }.

% erlcloud has no new/5. 
% also, arguments differ.
% erlcloud's new/4 expects accesskeyid, secretaccesskey, host, port
% erlcloud's signature is:
%   new(AccessKeyID::string(), SecretAccessKey::string(), Host::string(), Port::non_neg_integer()) -> aws_config()
% for now, attempting conversion to new/4
%
% this is called in oc_erchef in:
% src/oc_erchef/apps/chef_objects/src/chef_s3.erl, line 168
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

% is this used?
-spec delete_bucket(string()) -> ok.
delete_bucket(BucketName) ->
    erlcloud_s3:delete_bucket(BucketName).

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
    [{name, http_uri:decode(Name)} | Rest].

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

%% @doc Generate an S3 URL using Query String Request Authentication
%% [i think this link is for sigv2, not sigv4]
%% (see
%% http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth
%% for details).
%%
%% Note that this is **NOT** a complete implementation of the S3 Query
%% String Request Authentication signing protocol.  In particular, it
%% does nothing with "x-amz-*" headers, nothing for virtual hosted
%% buckets, and nothing for sub-resources.  It currently works for
%% relatively simple use cases (e.g., providing URLs to which
%% third-parties can upload specific files).
%%
%% Consult the official documentation (linked above) if you wish to
%% augment this function's capabilities.

-spec s3_url(atom(), string(), string(), integer() | {integer(), integer()},
             proplists:proplist(), aws_config()) -> binary().
s3_url(Method, BucketName0, Key0, {TTL, ExpireWin}, RawHeaders, Config) ->
    {Date, Lifetime} = make_expire_win(TTL, ExpireWin),
    s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Date, Config);
s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Config)
  when is_list(BucketName0), is_list(Key0), is_tuple(Config) ->
    [BucketName, Key] = [ms3_http:url_encode_loose(X) || X <- [BucketName0, Key0]],
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Config),
    iolist_to_binary(RequestURI).

%-spec s3_url(atom(), string(), string(), integer() | {integer(), integer()},
-spec s3_url(atom(), string(), string(), integer(),
             proplists:proplist(), string(), aws_config()) -> binary().
s3_url(Method, BucketName0, Key0, Lifetime, RawHeaders, Date, Config)
  when is_list(BucketName0), is_list(Key0), is_tuple(Config) ->
    [BucketName, Key] = [ms3_http:url_encode_loose(X) || X <- [BucketName0, Key0]],
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Date, Config),

    iolist_to_binary(RequestURI).

%-----------------------------------------------------------------------------------
% implementation of expiration windows for sigv4
% for making batches of cacheable presigned URLs
%
%       PAST       PRESENT      FUTURE
%                     |
% -----+-----+-----+--+--+-----+-----+-----+--
%      |     |     |  |  |     |     |     |   TIME
% -----+-----+-----+--+--+-----+-----+-----+--
%                  |     |
%   x-amz-date ----+     +---- x-amz-expires
%
%                  |-----| Lifetime
%
% 1) segment all of time into 'windows' of width expiry-window-size
% 2) align x-amz-date to nearest expiry-window boundary less than present time
% 3) align x-amz-expires to nearest expiry-window boundary greater than present time
%    while x-amz-expires - present < TTL, x-amz-expires += expiry-window-size
%-----------------------------------------------------------------------------------
-spec make_expire_win(non_neg_integer(), non_neg_integer()) -> {non_neg_integer(), non_neg_integer()}.
make_expire_win(TTL, ExpireWinSiz) ->
    Present = calendar:datetime_to_gregorian_seconds(calendar:now_to_universal_time(os:timestamp())),
    XAmzDateSec = Present div ExpireWinSiz * ExpireWinSiz,
    ExpirWinMult = ((TTL div ExpireWinSiz) + (case TTL rem ExpireWinSiz > 0 of true -> 1; _ -> 0 end)),
    XAmzExpires = case ExpirWinMult of 0 -> 1; _ -> ExpirWinMult end * ExpireWinSiz + XAmzDateSec,
    Lifetime = XAmzExpires - XAmzDateSec,
    {erlcloud_aws:iso_8601_basic_time(calendar:gregorian_seconds_to_datetime(XAmzDateSec)), Lifetime}.

% not sure if this is used? doesn't use config.
-spec get_object(string(), string(), proplists:proplist()) -> proplists:proplist().
get_object(BucketName, Key, Options) ->
    erlcloud_s3:get_object(BucketName, Key, Options).

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

%extract_metadata(Headers) ->
%    [{Key, Value} || {["x-amz-meta-"|Key], Value} <- Headers].

-spec get_object_torrent(string(), string()) -> proplists:proplist().
get_object_torrent(BucketName, Key) ->
    erlcloud_s3:get_object_torrent(BucketName, Key).

-spec get_object_torrent(string(), string(), aws_config()) -> proplists:proplist().
get_object_torrent(BucketName, Key, Config) ->
    erlcloud_s3:get_object_torrent(BucketName, Key, Config).

-spec list_object_versions(string(), proplists:proplist() | aws_config()) -> proplists:proplist().
list_object_versions(BucketName, Options) ->
    erlcloud_s3:list_object_versions(BucketName, Options).

% toggle port on host header (add port or remove it)
-spec get_host_toggleport(string(), aws_config()) -> string().
get_host_toggleport(Host, Config) ->
    case string:split(Host, ":", trailing) of
        [Host] ->
            Port = integer_to_list(Config#aws_config.s3_port),
            string:join([Host, Port], ":");
        ["http", _] ->
            Port = integer_to_list(Config#aws_config.s3_port),
            string:join([Host, Port], ":");
        ["https", _] ->
            Port = integer_to_list(Config#aws_config.s3_port),
            string:join([Host, Port], ":");
        [H, _] ->
            H
    end.

% construct url (scheme://host) from config
-spec get_url_noport(aws_config()) -> string().
get_url_noport(Config) ->
    UrlRaw  = get_url_port(Config),
    UrlTemp = string:trim(UrlRaw, trailing, "1234568790"),
    string:trim(UrlTemp, trailing, ":").

% construct url (scheme://host:port) from config
-spec get_url_port(aws_config()) -> string().
get_url_port(Config) ->
    Url0 = erlcloud_s3:get_object_url("", "", Config),
    Url1 = string:trim(Url0, trailing, "/"),
    case Config#aws_config.s3_port of
        80 ->
            % won't contain port if port == 80, so add it
            Url1 ++ ":80";
        _ ->
            Url1
    end.

-spec list_object_versions(string(), proplists:proplist(), aws_config()) -> proplists:proplist().
list_object_versions(BucketName, Options, Config) ->
    erlcloud_s3:list_object_versions(BucketName, Options, Config).

% is this used?
-spec put_object(string(), string(), iodata(), proplists:proplist(), [{string(), string()}] | aws_config()) -> proplists:proplist().
put_object(BucketName, Key, Value, Options, HTTPHeaders) ->
    erlcloud_s3:put_object(BucketName, Key, Value, Options, HTTPHeaders).

-spec put_object(string(), string(), iodata(), proplists:proplist(), [{string(), string()}], aws_config()) -> proplists:proplist().
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
    Signature = base64:encode(crypto:hmac(sha, SecretKey, StringToSign)),
    {StringToSign, ["AWS ", AccessKeyId, $:, Signature]}.

% currently unused, but may be necessary in the future
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
