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

-behavior(application).

%%%%%%%%%
-compile([export_all, nowarn_export_all]).
%%%%%%%%%

-export([new/2,
         new/3,
         new/4,
         new/5,
         create_bucket/3,
         create_bucket/4,
         delete_bucket/1,
         delete_bucket/2,
         get_bucket_attribute/2,
         get_bucket_attribute/3,
         list_buckets/0,
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
         %get_object_metadata/3,
         get_object_metadata/4,
         s3_url/6,
         s3_url/7,
         put_object/5,
         put_object/6,
         set_object_acl/3,
         set_object_acl/4]).

-export([manual_start/0,
         make_authorization/10,
         make_signed_url_authorization/5,
         universaltime/0]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("internal.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-include("erlcloud_aws.hrl").

%-export_type([config/0,
-export_type([aws_config/0,
              bucket_attribute_name/0,
              bucket_acl/0,
              location_constraint/0]).

% mini_s3 config and erlcloud config differ, but both are tuples/records.
% attempting to use aws_config record defined in erlcloud_aws.hrl.
% substituting config for aws_config  defined in erlcloud_aws.hrl.
%-opaque config() :: #config{}.

-type bucket_access_type() :: virtual_domain | path.

-type bucket_attribute_name() :: acl
                               | location
                               | logging
                               | request_payment
                               | versioning.

-type settable_bucket_attribute_name() :: acl
                                        | logging
                                        | request_payment
                                        | versioning.

-type bucket_acl() :: private
                    | public_read
                    | public_read_write
                    | authenticated_read
                    | bucket_owner_read
                    | bucket_owner_full_control.

-type location_constraint() :: none
                             | us_west_1
                             | eu.

%% This is a helper function that exists to make development just a
%% wee bit easier
-spec manual_start() -> ok.
manual_start() ->
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),
    application:start(inets).


%--------------------------------------------------------------------------
% new seems to produce a 'config' record (tuple).
% erlcloud's version does also, but the record isn't the same as mini_s3's.
% temporarily HACKED to pass back custom hardcoded authentication keys

%-spec new(string(), string()) -> config().
-spec new(string(), string()) -> aws_config().

%new(AccessKeyID, SecretAccessKey) ->
%    #config{
%     access_key_id=AccessKeyID,
%     secret_access_key=SecretAccessKey}.

% this results in an inconsistent s3_scheme/s3_port usage (see returned config)
new(AccessKeyID, SecretAccessKey) ->
    erlcloud_s3:new(AccessKeyID, SecretAccessKey).

%-spec new(string(), string(), string()) -> config().
-spec new(string(), string(), string()) -> aws_config().

%new(AccessKeyID, SecretAccessKey, Host) ->
%    #config{
%     access_key_id=AccessKeyID,
%     secret_access_key=SecretAccessKey,
%     s3_url=Host}.

new(AccessKeyID, SecretAccessKey, Host) ->
    % chef-server crams scheme://host:port all into into Host; erlcloud wants them separate.
    % Assume:
    %   Host   == scheme://domain:port | scheme://domain | domain:port | domain
    %   scheme == http | https
    %   port   == 80   | 443
    case string:split(Host, ":", all) of
        % Host == scheme://domain:port
        [Scheme0, [$/, $/ | Domain] | [Port0]] ->
            Scheme = Scheme0 ++ "://";
        % Host == scheme://domain
        [Scheme0, [$/, $/ | Domain]] ->
            Scheme = Scheme0 ++ "://",
            Port0  = undefined;
        % Host == domain:port
        [Domain, Port0] ->
            % crash on anything other than 80 or 443
            Scheme = case Port0 of "80" -> "http://"; "443" -> "https://" end;
        % Host == domain
        [Domain] ->
            Scheme = "https://",
            Port0  = undefined
    end,
    Port =
        case Port0 of
            undefined ->
                case Scheme of
                    "https://" -> 443;
                    "http://"  -> 80
                end;
            _ ->
                list_to_integer(Port0)
        end,
    Z = (erlcloud_s3:new(AccessKeyID, SecretAccessKey, Domain, Port))#aws_config{s3_scheme=Scheme},
%% HACK!! PROBABLY NOT FOR PRODUCTION!!
%% bookshelf wants bucketname after host e.g. https://api.chef-server.dev:443/bookshelf...
%% s3 wants bucketname before host (or it takes it either way) e.g. https://bookshelf.api.chef-server.dev:443...
case Z#aws_config.s3_host of "api.chef-server.dev" -> Z#aws_config{s3_bucket_after_host=true}; _ -> Z end.

% erlcloud wants accesskey, secretaccesskey, host, port.
% mini_s3 wants accesskey, secretaccesskey, host, bucketaccesstype

%-spec new(string(), string(), string(), bucket_access_type()) -> config().
-spec new(string(), string(), string(), bucket_access_type()) -> aws_config().

%new(AccessKeyID, SecretAccessKey, Host, BucketAccessType) ->
%    #config{
%     access_key_id=AccessKeyID,
%     secret_access_key=SecretAccessKey,
%     s3_url=Host,
%     bucket_access_type=BucketAccessType}.

new(AccessKeyID, SecretAccessKey, Host, BucketAccessType) ->
io:format("~ncalling mini_s3:new/4 - is this ever used? (YES, it is)"),
io:format("~nHost=~p", [Host]),
io:format("~nBucketAccessType=~p", [BucketAccessType]),
    % convert mini_s3 new/4 to erlcloud
    {BucketAccessMethod, BucketAfterHost} = case BucketAccessType of path -> {path, true}; _ -> {vhost, false} end,
    Config = new(AccessKeyID, SecretAccessKey, Host),
    Config#aws_config{
        %access_key_id=AccessKeyID,
        %secret_access_key=SecretAccessKey,
        %s3_url=Host,
        %ssl_options=SslOpts,
        s3_bucket_access_method=BucketAccessMethod,
        s3_bucket_after_host=BucketAfterHost
    }.

%-spec new(string(), string(), string(), bucket_access_type(), proplists:proplist()) -> config().
-spec new(string(), string(), string(), bucket_access_type(), proplists:proplist()) -> aws_config().

% erlcloud has no new/5. 
% also, arguments differ.  erlcloud's new/4 expects accesskeyid, secretaccesskey, host, port)
% erlcloud's signature is:
%   new(AccessKeyID::string(), SecretAccessKey::string(), Host::string(), Port::non_neg_integer()) -> aws_config()
% for now, attempting conversion to new/4
%
% this is called in oc_erchef app in:
%   src/oc_erchef/apps/chef_objects/src/chef_s3.erl, line 168

new(AccessKeyID, SecretAccessKey, Host, BucketAccessType, _SslOpts) ->
    io:format("~nmini_s3:new/5 doesn't know what to do with SslOpts - dropping for now"),
    new(AccessKeyID, SecretAccessKey, Host, BucketAccessType).
%--------------------------------------------------------------------------



%--------------------------------------------------------------------------
-define(XMLNS_S3, "http://s3.amazonaws.com/doc/2006-03-01/").

-spec copy_object(string(), string(), string(), string(), proplists:proplist()) -> proplists:proplist().
%copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options) ->
%    copy_object(DestBucketName, DestKeyName, SrcBucketName,
%                SrcKeyName, Options, default_config()).

copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options) ->
    io:format("~n~nmini_s3:copy_object(~p, ~p, ~p, ~p, ~p)", [DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options]),
    erlcloud_s3:copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options).

%-spec copy_object(string(), string(), string(), string(),
%                  proplists:proplist(), config()) -> proplists:proplist().
%copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, Config) ->
%    SrcVersion = case proplists:get_value(version_id, Options) of
%                     undefined -> "";
%                     VersionID -> ["?versionId=", VersionID]
%                 end,
%    RequestHeaders =
%        [{"x-amz-copy-source", [SrcBucketName, $/, SrcKeyName, SrcVersion]},
%         {"x-amz-metadata-directive",
%          proplists:get_value(metadata_directive, Options)},
%         {"x-amz-copy-source-if-match", proplists:get_value(if_match, Options)},
%         {"x-amz-copy-source-if-none-match",
%          proplists:get_value(if_none_match, Options)},
%         {"x-amz-copy-source-if-unmodified-since",
%          proplists:get_value(if_unmodified_since, Options)},
%         {"x-amz-copy-source-if-modified-since",
%          proplists:get_value(if_modified_since, Options)},
%         {"x-amz-acl", encode_acl(proplists:get_value(acl, Options))}],
%    {Headers, _Body} = s3_request(Config, put, DestBucketName, [$/|DestKeyName],
%                                  "", [], <<>>, RequestHeaders),
%    [{copy_source_version_id,
%      proplists:get_value("x-amz-copy-source-version-id", Headers, "false")},
%     {version_id, proplists:get_value("x-amz-version-id", Headers, "null")}].

copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, Config) ->
    io:format("~n~nmini_s3:copy_object(~p, ~p, ~p, ~p, ~p, ~0p)", [DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, "config"]),
    erlcloud_s3:copy_object(DestBucketName, DestKeyName, SrcBucketName, SrcKeyName, Options, Config).

%-spec create_bucket(string(), bucket_acl(), location_constraint()) -> ok.
%
%create_bucket(BucketName, ACL, LocationConstraint) ->
%    create_bucket(BucketName, ACL, LocationConstraint, default_config()).

create_bucket(BucketName, ACL, LocationConstraint) ->
    io:format("~n~nmini_s3:create_bucket(~p, ~p, ~p)", [BucketName, ACL, LocationConstraint]),
    erlcloud_s3:create_bucket(BucketName, ACL, LocationConstraint).

%-spec create_bucket(string(), bucket_acl(), location_constraint(), config()) -> ok.
%
%create_bucket(BucketName, ACL, LocationConstraint, Config)
%  when is_list(BucketName), is_atom(ACL), is_atom(LocationConstraint) ->
%    Headers = case ACL of
%                  private -> [];  %% private is the default
%                  _       -> [{"x-amz-acl", encode_acl(ACL)}]
%              end,
%    POSTData = case LocationConstraint of
%                   none -> <<>>;
%                   Location when Location =:= eu; Location =:= us_west_1 ->
%                       LocationName = case Location of
%                                          eu -> "EU";
%                                          us_west_1 -> "us-west-1"
%                                      end,
%                       XML = {'CreateBucketConfiguration', [{xmlns, ?XMLNS_S3}],
%                              [{'LocationConstraint', [LocationName]}]},
%                       list_to_binary(xmerl:export_simple([XML], xmerl_xml))
%               end,
%    s3_simple_request(Config, put, BucketName, "/", "", [], POSTData, Headers).

create_bucket(BucketName, ACL, LocationConstraint, Config) ->
    io:format("~n~nmini_s3:create_bucket(~p, ~p, ~p, ~0p)", [BucketName, ACL, LocationConstraint, "config"]),
    erlcloud_s3:create_bucket(BucketName, ACL, LocationConstraint, Config).

encode_acl(undefined)                 -> undefined;
encode_acl(private)                   -> "private";
encode_acl(public_read)               -> "public-read";
encode_acl(public_read_write)         -> "public-read-write";
encode_acl(authenticated_read)        -> "authenticated-read";
encode_acl(bucket_owner_read)         -> "bucket-owner-read";
encode_acl(bucket_owner_full_control) -> "bucket-owner-full-control".

%-spec delete_bucket(string()) -> ok.
%
%delete_bucket(BucketName) ->
%    delete_bucket(BucketName, default_config()).

delete_bucket(BucketName) ->
    io:format("~n~nmini_s3:delete_bucket(~p)", [BucketName]),
    erlcloud_s3:delete_bucket(BucketName).

%-spec delete_bucket(string(), config()) -> ok.
%
%delete_bucket(BucketName, Config)
%  when is_list(BucketName) ->
%    s3_simple_request(Config, delete, BucketName, "/", "", [], <<>>, []).

delete_bucket(BucketName, Config) ->
    io:format("~n~nmini_s3:delete_bucket(~p, ~0p)", [BucketName, config]),
    erlcloud_s3:delete_bucket(BucketName, Config).

%-spec delete_object(string(), string()) -> proplists:proplist().
%
%delete_object(BucketName, Key) ->
%    delete_object(BucketName, Key, default_config()).

delete_object(BucketName, Key) ->
    io:format("~n~nmini_s3:delete_object(~p, ~p)", [BucketName, Key]),
    erlcloud_s3:delete_object(BucketName, Key).

%-spec delete_object(string(), string(), config()) -> proplists:proplist().
%
%delete_object(BucketName, Key, Config)
%  when is_list(BucketName), is_list(Key) ->
%    {Headers, _Body} = s3_request(Config, delete,
%                                  BucketName, [$/|Key], "", [], <<>>, []),
%    Marker = proplists:get_value("x-amz-delete-marker", Headers, "false"),
%    Id = proplists:get_value("x-amz-version-id", Headers, "null"),
%    [{delete_marker, list_to_existing_atom(Marker)},
%     {version_id, Id}].

delete_object(BucketName, Key, Config) ->
    io:format("~n~nmini_s3:delete_object(~p, ~p, ~0p)", [BucketName, Key, config]),
    erlcloud_s3:delete_object(BucketName, Key, Config).

%-spec delete_object_version(string(), string(), string()) ->
%                                   proplists:proplist().
%
%delete_object_version(BucketName, Key, Version) ->
%    delete_object_version(BucketName, Key, Version, default_config()).

delete_object_version(BucketName, Key, Version) ->
    io:format("~n~nmini_s3:delete_object_version(~p, ~p, ~p)", [BucketName, Key, Version]),
    erlcloud_s3:delete_object_version(BucketName, Key, Version).

%-spec delete_object_version(string(), string(), string(), config()) ->
%                                   proplists:proplist().
%
%delete_object_version(BucketName, Key, Version, Config)
%  when is_list(BucketName),
%       is_list(Key),
%       is_list(Version)->
%    {Headers, _Body} = s3_request(Config, delete, BucketName, [$/|Key],
%                                  "versionId=" ++ Version, [], <<>>, []),
%    Marker = proplists:get_value("x-amz-delete-marker", Headers, "false"),
%    Id = proplists:get_value("x-amz-version-id", Headers, "null"),
%    [{delete_marker, list_to_existing_atom(Marker)},
%     {version_id, Id}].

delete_object_version(BucketName, Key, Version, Config) ->
    io:format("~n~nmini_s3:delete_object_version(~p, ~p, ~p, ~0p)", [BucketName, Key, Version, config]),
    erlcloud_s3:delete_object_version(BucketName, Key, Version, Config).

%-spec list_buckets() -> proplists:proplist().
%
%list_buckets() ->
%    list_buckets(default_config()).

list_buckets() ->
    io:format("~n~nmini_s3:list_buckets()"),
    erlcloud_s3:list_buckets().

%-spec list_buckets(config()) -> proplists:proplist().
-spec list_buckets(aws_config()) -> proplists:proplist().

%list_buckets(Config) ->
%    Doc = s3_xml_request(Config, get, "", "/", "", [], <<>>, []),
%    Buckets = [extract_bucket(Node)
%               || Node <- xmerl_xpath:string("/*/Buckets/Bucket", Doc)],
%    [{buckets, Buckets}].

list_buckets(Config) ->
    io:format("~n~nmini_s3:list_buckets(~0p)", [config]),
    erlcloud_s3:list_buckets(Config).

%-spec list_objects(string(), proplists:proplist()) -> proplists:proplist().
%
%list_objects(BucketName, Options) ->
%    list_objects(BucketName, Options, default_config()).

list_objects(BucketName, Options) ->
    io:format("~n~nmini_s3:list_objects(~p, ~p)", [BucketName, Options]),
    erlcloud_s3:list_objects(BucketName, Options).

%-spec list_objects(string(), proplists:proplist(), config()) ->
%                          proplists:proplist().
%
%list_objects(BucketName, Options, Config)
%  when is_list(BucketName),
%       is_list(Options) ->
%    Params = [{"delimiter", proplists:get_value(delimiter, Options)},
%              {"marker", proplists:get_value(marker, Options)},
%              {"max-keys", proplists:get_value(max_keys, Options)},
%              {"prefix", proplists:get_value(prefix, Options)}],
%    Doc = s3_xml_request(Config, get, BucketName, "/", "", Params, <<>>, []),
%    Attributes = [{name, "Name", text},
%                  {prefix, "Prefix", text},
%                  {marker, "Marker", text},
%                  {delimiter, "Delimiter", text},
%                  {max_keys, "MaxKeys", integer},
%                  {is_truncated, "IsTruncated", boolean},
%                  {contents, "Contents", fun extract_contents/1}],
%    ms3_xml:decode(Attributes, Doc).

list_objects(BucketName, Options, Config) ->
    io:format("~n~nmini_s3:list_objects(~p, ~p, ~0p)", [BucketName, Options, config]),
    erlcloud_s3:list_objects(BucketName, Options, Config).

extract_contents(Nodes) ->
    Attributes = [{key, "Key", text},
                  {last_modified, "LastModified", time},
                  {etag, "ETag", text},
                  {size, "Size", integer},
                  {storage_class, "StorageClass", text},
                  {owner, "Owner", fun extract_user/1}],
    [ms3_xml:decode(Attributes, Node) || Node <- Nodes].

extract_user([Node]) ->
    Attributes = [{id, "ID", text},
                  {display_name, "DisplayName", optional_text}],
    ms3_xml:decode(Attributes, Node).

%-spec get_bucket_attribute(string(), bucket_attribute_name()) -> term().
%
%get_bucket_attribute(BucketName, AttributeName) ->
%    get_bucket_attribute(BucketName, AttributeName, default_config()).

get_bucket_attribute(BucketName, AttributeName) ->
    io:format("~n~nmini_s3:get_bucket_attribute(~p, ~p)", [BucketName, AttributeName]),
    erlcloud_s3:get_bucket_attribute(BucketName, AttributeName).

%-spec get_bucket_attribute(string(), bucket_attribute_name(), config()) -> term().
%
%get_bucket_attribute(BucketName, AttributeName, Config)
%  when is_list(BucketName), is_atom(AttributeName) ->
%    Attr = case AttributeName of
%               acl             -> "acl";
%               location        -> "location";
%               logging         -> "logging";
%               request_payment -> "requestPayment";
%               versioning      -> "versioning"
%           end,
%    Doc = s3_xml_request(Config, get, BucketName, "/", Attr, [], <<>>, []),
%    case AttributeName of
%        acl ->
%            Attributes = [{owner, "Owner", fun extract_user/1},
%                          {access_control_list,
%                           "AccessControlList/Grant", fun extract_acl/1}],
%            ms3_xml:decode(Attributes, Doc);
%        location ->
%            ms3_xml:get_text("/LocationConstraint", Doc);
%        logging ->
%            case xmerl_xpath:string("/BucketLoggingStatus/LoggingEnabled", Doc) of
%                [] ->
%                    {enabled, false};
%                [LoggingEnabled] ->
%                    Attributes = [{target_bucket, "TargetBucket", text},
%                                  {target_prefix, "TargetPrefix", text},
%                                  {target_trants, "TargetGrants/Grant", fun extract_acl/1}],
%                    [{enabled, true}|ms3_xml:decode(Attributes, LoggingEnabled)]
%            end;
%        request_payment ->
%            case ms3_xml:get_text("/RequestPaymentConfiguration/Payer", Doc) of
%                "Requester" -> requester;
%                _           -> bucket_owner
%            end;
%        versioning ->
%            case ms3_xml:get_text("/VersioningConfiguration/Status", Doc) of
%                "Enabled"   -> enabled;
%                "Suspended" -> suspended;
%                _           -> disabled
%            end
%    end.

get_bucket_attribute(BucketName, AttributeName, Config) ->
    erlcloud_s3:get_bucket_attribute(BucketName, AttributeName, Config).

extract_acl(ACL) ->
    [extract_grant(Item) || Item <- ACL].

extract_grant(Node) ->
    [{grantee, extract_user(xmerl_xpath:string("Grantee", Node))},
     {permission, decode_permission(ms3_xml:get_text("Permission", Node))}].

encode_permission(full_control) -> "FULL_CONTROL";
encode_permission(write)        -> "WRITE";
encode_permission(write_acp)    -> "WRITE_ACP";
encode_permission(read)         -> "READ";
encode_permission(read_acp) -> "READ_ACP".

decode_permission("FULL_CONTROL") -> full_control;
decode_permission("WRITE")        -> write;
decode_permission("WRITE_ACP")    -> write_acp;
decode_permission("READ")         -> read;
decode_permission("READ_ACP")     -> read_acp.


%% @doc Canonicalizes a proplist of {"Header", "Value"} pairs by
%% lower-casing all the Headers.
-spec canonicalize_headers([{string() | binary() | atom(), Value::string()}]) ->
                                  [{LowerCaseHeader::string(), Value::string()}].
canonicalize_headers(Headers) ->
    [{string:to_lower(to_string(H)), V} || {H, V} <- Headers ].

-spec to_string(atom() | binary() | string()) -> string().
to_string(A) when is_atom(A) ->
    erlang:atom_to_list(A);
to_string(B) when is_binary(B) ->
    erlang:binary_to_list(B);
to_string(S) when is_list(S) ->
    S.

%% @doc Retrieves a value from a set of canonicalized headers.  The
%% given header should already be canonicalized (i.e., lower-cased).
%% Returns the value or the empty string if no such value was found.
-spec retrieve_header_value(Header::string(),
                            AllHeaders::[{Header::string(), Value::string()}]) ->
                                   string().
retrieve_header_value(Header, AllHeaders) ->
    proplists:get_value(Header, AllHeaders, "").

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

%% Abstraction of universaltime, so it can be mocked via meck
-spec universaltime() -> calendar:datetime().
universaltime() ->
    erlang:universaltime().

-spec if_not_empty(string(), iolist()) -> iolist().
if_not_empty("", _V) ->
    "";
if_not_empty(_, Value) ->
    Value.

%-spec format_s3_uri(config(), string()) -> string().
-spec format_s3_uri(aws_config(), string()) -> string().
%format_s3_uri(#config{s3_url=S3Url, bucket_access_type=BAccessType}, Host) ->
format_s3_uri(Config, Host) ->
    % leaving off explicitly adding port for now, as this seems to be done automagically?
    %S3Url = Config#aws_config.s3_scheme ++ Config#aws_config.s3_host, % ++ ":" ++ integer_to_list(Config#aws_config.s3_port),
    S3Url = Config#aws_config.s3_host,
    Scheme0 = Config#aws_config.s3_scheme,
    % if scheme doesn't have ://, add it . if it does, leave it alone.  this was necessary because both
    % ways were being passed-in, but weren't being handled, causing errors
    Scheme = case string:split(Scheme0, "://", leading) of [Scheme0] -> Scheme0++"://"; [_, []] -> Scheme0 end,
    Port0 = integer_to_list(Config#aws_config.s3_port),
    BAccessType = Config#aws_config.s3_bucket_access_method,
io:format("~n~nmini_s3:format_s3_uri: Config=~0p Host=~p Scheme=~p, S3Url=~p BAccessType=~p", [config, Host, Scheme, S3Url, BAccessType]),
    {ok,{Protocol,UserInfo,Domain,Port,_Uri,_QueryString}} =
        %http_uri:parse(S3Url, [{ipv6_host_with_brackets, true}]),
        http_uri:parse(Scheme++S3Url++":"++Port0, [{ipv6_host_with_brackets, true}]),
    case BAccessType of
        %virtual_hosted ->
        vhost ->
            lists:flatten([erlang:atom_to_list(Protocol), "://",
                           if_not_empty(Host, [Host, $.]),
                           if_not_empty(UserInfo, [UserInfo, "@"]),
                           Domain, ":", erlang:integer_to_list(Port)]);
        path ->
            lists:flatten([erlang:atom_to_list(Protocol), "://",
                           if_not_empty(UserInfo, [UserInfo, "@"]),
                           Domain, ":", erlang:integer_to_list(Port),
                           if_not_empty(Host, [$/, Host])])
    end.

% NOTE: erlcloud doesn't have s3_url function
% this appears to be a sigv2 "presigned" or "query string request" for enabling direct third-party browser access
% to private Amazon S3 data without proxying the request. erlcloud does not have this capability at this time.
% converted to sigv4

%% @doc Generate an S3 URL using Query String Request Authentication
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
%             proplists:proplist(), config()) -> binary().
s3_url(Method, BucketName, Key, Lifetime, RawHeaders,
       Config = #aws_config{access_key_id=AccessKey,
                        secret_access_key=SecretKey})
  when is_list(BucketName), is_list(Key), is_tuple(Config) ->
    io:format("~n~n----------------------------------------"),
    io:format("~nmini_s3:s3_url/6"
        "~nmethod = ~p~nbucketname = ~p~nkey = ~p~nlifetime = ~p~nrawheaders = ~p", [Method, BucketName, Key, Lifetime, RawHeaders]),
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Config),
    io:format("~n~nfinished mini_s3:s3_url COMPLETE.  RequestURI = ~p~n~n", [RequestURI]),
    iolist_to_binary(RequestURI).

-spec s3_url(atom(), string(), string(), integer() | {integer(), integer()},
             proplists:proplist(), string(), aws_config()) -> binary().
s3_url(Method, BucketName, Key, Lifetime, RawHeaders, Date,
       Config = #aws_config{access_key_id=AccessKey,
                        secret_access_key=SecretKey})
  when is_list(BucketName), is_list(Key), is_tuple(Config) ->
    io:format("~n~n----------------------------------------"),
    io:format("~nmini_s3:s3_url/7"
        "~nmethod = ~p~nbucketname = ~p~nkey = ~p~nlifetime = ~p~nrawheaders = ~p~ndate = ~p", [Method, BucketName, Key, Lifetime, RawHeaders, Date]),
    RequestURI = erlcloud_s3:make_presigned_v4_url(Lifetime, BucketName, Method, Key, [], RawHeaders, Date, Config),

%    Expires = erlang:integer_to_list(expiration_time(Lifetime)),
%
%    Path = lists:flatten([$/, BucketName, $/ , Key]),
%    CanonicalizedResource = ms3_http:url_encode_loose(Path),
%
%    {_StringToSign, Signature} = mini_s3:make_signed_url_authorization(SecretKey, Method,
%                                                               CanonicalizedResource,
%                                                               Expires, RawHeaders),
%
%    RequestURI = iolist_to_binary([
%                                   format_s3_uri(Config, ""), CanonicalizedResource,
%                                   $?, "AWSAccessKeyId=", AccessKey,
%                                   $&, "Expires=", Expires,
%                                   $&, "Signature=", ms3_http:url_encode_loose(Signature)
%                                  ]),
io:format("~n~nfinished mini_s3:s3_url COMPLETE.  RequestURI = ~p~n~n", [RequestURI]),
    iolist_to_binary(RequestURI).

make_signed_url_authorization(SecretKey, Method, CanonicalizedResource,
                              Expires, RawHeaders) ->
    Headers = canonicalize_headers(RawHeaders),

    HttpMethod = string:to_upper(atom_to_list(Method)),

    ContentType = retrieve_header_value("content-type", Headers),
    ContentMD5 = retrieve_header_value("content-md5", Headers),

    %% We don't currently use this, but I'm adding a placeholder for future enhancements See
    %% the URL in the docstring for details
    CanonicalizedAMZHeaders = "",


    StringToSign = lists:flatten([HttpMethod, $\n,
                                  ContentMD5, $\n,
                                  ContentType, $\n,
                                  Expires, $\n,
                                  CanonicalizedAMZHeaders, %% IMPORTANT: No newline here!!
                                  CanonicalizedResource
                                 ]),
io:format("~n~nmini_s3:make_signed_url_authorization: SecretKey=~p StringToSign=~0p", [SecretKey, StringToSign]),
    Signature = base64:encode(crypto:hmac(sha, SecretKey, StringToSign)),
    {StringToSign, Signature}.


%-spec get_object(string(), string(), proplists:proplist()) ->
%                        proplists:proplist().
%
%get_object(BucketName, Key, Options) ->
%    get_object(BucketName, Key, Options, default_config()).

get_object(BucketName, Key, Options) ->
    io:format("~n~nmini_s3:get_object(~p, ~p, ~p)", [BucketName, Key, Options]),
    erlcloud_s3:get_object(BucketName, Key, Options).

%-spec get_object(string(), string(), proplists:proplist(), config()) ->
%                        proplists:proplist().
%
%get_object(BucketName, Key, Options, Config) ->
%    RequestHeaders = [{"Range", proplists:get_value(range, Options)},
%                      {"If-Modified-Since", proplists:get_value(if_modified_since, Options)},
%                      {"If-Unmodified-Since", proplists:get_value(if_unmodified_since, Options)},
%                      {"If-Match", proplists:get_value(if_match, Options)},
%                      {"If-None-Match", proplists:get_value(if_none_match, Options)}],
%    Subresource = case proplists:get_value(version_id, Options) of
%                      undefined -> "";
%                      Version   -> ["versionId=", Version]
%                  end,
%    {Headers, Body} = s3_request(Config, get, BucketName, [$/|Key], Subresource, [], <<>>, RequestHeaders),
%    [{etag, proplists:get_value("etag", Headers)},
%     {content_length, proplists:get_value("content-length", Headers)},
%     {content_type, proplists:get_value("content-type", Headers)},
%     {delete_marker, list_to_existing_atom(proplists:get_value("x-amz-delete-marker", Headers, "false"))},
%     {version_id, proplists:get_value("x-amz-version-id", Headers, "null")},
%     {content, list_to_binary(Body)}|
%     extract_metadata(Headers)].

get_object(BucketName, Key, Options, Config) ->
    io:format("~n~nmini_s3:get_object(~p, ~p, ~p ~0p)", [BucketName, Key, Options, config]),
    erlcloud_s3:get_object(BucketName, Key, Options, Config).

%-spec get_object_acl(string(), string()) -> proplists:proplist().
%
%get_object_acl(BucketName, Key) ->
%    get_object_acl(BucketName, Key, default_config()).

get_object_acl(BucketName, Key) ->
    io:format("~n~nmini_s3:get_object_acl(~p, ~p)", [BucketName, Key]),
    erlcloud_s3:get_object_acl(BucketName, Key).

%-spec get_object_acl(string(), string(), proplists:proplist() | config()) -> proplists:proplist().
%
%get_object_acl(BucketName, Key, Config)
%  when is_record(Config, config) ->
%    get_object_acl(BucketName, Key, [], Config);
%get_object_acl(BucketName, Key, Options) ->
%    get_object_acl(BucketName, Key, Options, default_config()).

get_object_acl(BucketName, Key, Config) ->
    io:format("~n~nmini_s3:get_object_acl(~p, ~p, ~0p)", [BucketName, Key, config]),
    erlcloud_s3:get_object_acl(BucketName, Key, Config).

%-spec get_object_acl(string(), string(), proplists:proplist(), config()) -> proplists:proplist().
%
%get_object_acl(BucketName, Key, Options, Config)
%  when is_list(BucketName), is_list(Key), is_list(Options) ->
%    Subresource = case proplists:get_value(version_id, Options) of
%                      undefined -> "";
%                      Version   -> ["&versionId=", Version]
%                  end,
%    Doc = s3_xml_request(Config, get, BucketName, [$/|Key], "acl" ++ Subresource, [], <<>>, []),
%    Attributes = [{owner, "Owner", fun extract_user/1},
%                  {access_control_list, "AccessControlList/Grant", fun extract_acl/1}],
%    ms3_xml:decode(Attributes, Doc).

get_object_acl(BucketName, Key, Options, Config) ->
    io:format("~n~nmini_s3:get_object_acl(~p, ~p, ~p, ~0p)", [BucketName, Key, Options, config]),
    erlcloud_s3:get_object_acl(BucketName, Key, Options, Config).

%-spec get_object_metadata(string(), string(), proplists:proplist()) -> proplists:proplist().
%
%get_object_metadata(BucketName, Key, Options) ->
%    get_object_metadata(BucketName, Key, Options, default_config()).


% erlcloud get_object_metadata/3 only supports passing a bucketname, key, and config.
% converting to 4 parameter version and using default config.
% is default config even useful at all, or will it just produce errors?
%get_object_metadata(BucketName, Key, Options) ->
%    io:format("~n~nmini_s3:get_object_metadata(~p, ~p, ~p, ~0p)", [BucketName, Key, Options, "default_config()"]),
%    erlcloud_s3:get_object_metadata(BucketName, Key, Options, default_config()).


% testing this code pursuant to investigation of pedant test 500s in checking file checksums
% even if this works, will it break what was already working (retest pointing oc-erchef to s3 vs bookshelf)?

-spec get_object_metadata(string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().

get_object_metadata(BucketName, Key, Options, Config) ->
    io:format("~nmini_s3:get_object_metadata/4"),
    % TODO: do a search first to make sure this header isn't there before adding (proplists:get_value)
    %Options = [{"x-amz-content-sha256", "UNSIGNED-PAYLOAD"}, {"content-length", "0"}, {"x-amz-decoded-content-length", "0"} | Options0],
    Z = erlcloud_s3:get_object_metadata(BucketName, Key, Options, Config),
    io:format("~nmini_s3:get_object_metadata/4 result = ~p", [Z]),
    Z.
%io:format("~nrouting through ORIGINAL mini_s3:get_object_metadata(~p, ~p, ~p, ~p)", [BucketName, Key, Options, "config"]),
%io:format("~n----------------------------"),
%io:format("~nmini_s3:get_object_metadata(~p, ~p, ~p, ~p)", [BucketName, Key, Options, "config"]),
%    RequestHeaders = [{"If-Modified-Since", proplists:get_value(if_modified_since, Options)},
%                      {"If-Unmodified-Since", proplists:get_value(if_unmodified_since, Options)},
%                      {"If-Match", proplists:get_value(if_match, Options)},
%                      {"If-None-Match", proplists:get_value(if_none_match, Options)}],
%    Subresource = case proplists:get_value(version_id, Options) of
%                      undefined -> "";
%                      Version   -> ["versionId=", Version]
%                  end,
%io:format("~nsubresource: ~p", [Subresource]),
%Z = erlcloud_s3:get_object_metadata(BucketName, Key, Options ++ RequestHeaders, Config),
%io:format("~nreturn value from get_object_metadata: ~p", [Z]),
%io:format("~n----------------------------"),
%%    {Headers, _Body} = s3_request(Config, head, BucketName, [$/|Key], Subresource, [], <<>>, RequestHeaders),
%{Headers, _Body} = Z,
%    [{last_modified, proplists:get_value("last-modified", Headers)},
%     {etag, proplists:get_value("etag", Headers)},
%     {content_length, proplists:get_value("content-length", Headers)},
%     {content_type, proplists:get_value("content-type", Headers)},
%     {delete_marker, list_to_existing_atom(proplists:get_value("x-amz-delete-marker", Headers, "false"))},
%     {version_id, proplists:get_value("x-amz-version-id", Headers, "false")}|extract_metadata(Headers)].

%get_object_metadata(BucketName, Key, Options, Config) ->
%io:format("~nmini_s3:get_object_metadata(~p, ~p, ~p, ~p)", [BucketName, Key, Options, "config"]),
%    erlcloud_s3:get_object_metadata(BucketName, Key, Options, Config).

extract_metadata(Headers) ->
    [{Key, Value} || {["x-amz-meta-"|Key], Value} <- Headers].

%-spec get_object_torrent(string(), string()) -> proplists:proplist().
%
%get_object_torrent(BucketName, Key) ->
%    get_object_torrent(BucketName, Key, default_config()).

get_object_torrent(BucketName, Key) ->
    io:format("~n~nmini_s3:get_object_torrent(~p, ~p)", [BucketName, Key]),
    erlcloud_s3:get_object_torrent(BucketName, Key).

%-spec get_object_torrent(string(), string(), config()) -> proplists:proplist().
%
%get_object_torrent(BucketName, Key, Config) ->
%    {Headers, Body} = s3_request(Config, get, BucketName, [$/|Key], "torrent", [], <<>>, []),
%    [{delete_marker, list_to_existing_atom(proplists:get_value("x-amz-delete-marker", Headers, "false"))},
%     {version_id, proplists:get_value("x-amz-delete-marker", Headers, "false")},
%     {torrent, list_to_binary(Body)}].

get_object_torrent(BucketName, Key, Config) ->
    io:format("~n~nmini_s3:get_object_torrent(~p, ~p, ~0p)", [BucketName, Key, config]),
    erlcloud_s3:get_object_torrent(BucketName, Key, Config).

%-spec list_object_versions(string(), proplists:proplist()) -> proplists:proplist().
%
%list_object_versions(BucketName, Options) ->
%    list_object_versions(BucketName, Options, default_config()).

list_object_versions(BucketName, Options) ->
    io:format("~n~nmini_s3:list_object_versions(~p, ~p)", [BucketName, Options]),
    erlcloud_s3:list_object_versions(BucketName, Options).

%-spec list_object_versions(string(), proplists:proplist(), config()) -> proplists:proplist().
%
%list_object_versions(BucketName, Options, Config)
%  when is_list(BucketName), is_list(Options) ->
%    Params = [{"delimiter", proplists:get_value(delimiter, Options)},
%              {"key-marker", proplists:get_value(key_marker, Options)},
%              {"max-keys", proplists:get_value(max_keys, Options)},
%              {"prefix", proplists:get_value(prefix, Options)},
%              {"version-id-marker", proplists:get_value(version_id_marker, Options)}],
%    Doc = s3_xml_request(Config, get, BucketName, "/", "versions", Params, <<>>, []),
%    Attributes = [{name, "Name", text},
%                  {prefix, "Prefix", text},
%                  {key_marker, "KeyMarker", text},
%                  {next_key_marker, "NextKeyMarker", optional_text},
%                  {version_id_marker, "VersionIdMarker", text},
%                  {next_version_id_marker, "NextVersionIdMarker", optional_text},
%                  {max_keys, "MaxKeys", integer},
%                  {is_truncated, "Istruncated", boolean},
%                  {versions, "Version", fun extract_versions/1},
%                  {delete_markers, "DeleteMarker", fun extract_delete_markers/1}],
%    ms3_xml:decode(Attributes, Doc).

list_object_versions(BucketName, Options, Config) ->
    io:format("~n~nmini_s3:list_object_versions(~p, ~p, ~0p)", [BucketName, Options, config]),
    erlcloud_s3:list_object_versions(BucketName, Options, Config).

extract_versions(Nodes) ->
    [extract_version(Node) || Node <- Nodes].

extract_version(Node) ->
    Attributes = [{key, "Key", text},
                  {version_id, "VersionId", text},
                  {is_latest, "IsLatest", boolean},
                  {etag, "ETag", text},
                  {size, "Size", integer},
                  {owner, "Owner", fun extract_user/1},
                  {storage_class, "StorageClass", text}],
    ms3_xml:decode(Attributes, Node).

extract_delete_markers(Nodes) ->
    [extract_delete_marker(Node) || Node <- Nodes].

extract_delete_marker(Node) ->
    Attributes = [{key, "Key", text},
                  {version_id, "VersionId", text},
                  {is_latest, "IsLatest", boolean},
                  {owner, "Owner", fun extract_user/1}],
    ms3_xml:decode(Attributes, Node).

extract_bucket(Node) ->
    ms3_xml:decode([{name, "Name", text},
                    {creation_date, "CreationDate", time}],
                   Node).

%-spec put_object(string(),
%                 string(),
%                 iolist(),
%                 proplists:proplist(),
%                 [{string(), string()}]) -> [{'version_id', _}, ...].
%
%put_object(BucketName, Key, Value, Options, HTTPHeaders) ->
%    put_object(BucketName, Key, Value, Options, HTTPHeaders, default_config()).

put_object(BucketName, Key, Value, Options, HTTPHeaders) ->
    io:format("~n~nmini_s3:put_object(~p, ~p, ~p, ~p, ~p)", [BucketName, Key, Value, Options, HTTPHeaders]),
    erlcloud_s3:put_object(BucketName, Key, Value, Options, HTTPHeaders).

%-spec put_object(string(),
%                 string(),
%                 iolist(),
%                 proplists:proplist(),
%                 [{string(), string()}],
%                 config()) -> [{'version_id', _}, ...].
%
%put_object(BucketName, Key, Value, Options, HTTPHeaders, Config)
%  when is_list(BucketName), is_list(Key), is_list(Value) orelse is_binary(Value),
%       is_list(Options) ->
%    ContentType = proplists:get_value("content-type", HTTPHeaders, "application/octet_stream"),
%    FilteredHTTPHeaders = proplists:delete("content-type", HTTPHeaders),
%
%    RequestHeaders = [{"x-amz-acl", encode_acl(proplists:get_value(acl, Options))}|FilteredHTTPHeaders]
%        ++ [{["x-amz-meta-"|string:to_lower(MKey)], MValue} ||
%               {MKey, MValue} <- proplists:get_value(meta, Options, [])],
%    POSTData = {iolist_to_binary(Value), ContentType},
%    {Headers, _Body} = s3_request(Config, put, BucketName, [$/|Key], "", [],
%                                  POSTData, RequestHeaders),
%    [{version_id, proplists:get_value("x-amz-version-id", Headers, "null")}].

put_object(BucketName, Key, Value, Options, HTTPHeaders, Config) ->
    io:format("~n~nmini_s3:put_object(~p, ~p, ~p, ~p, ~p, ~0p)", [BucketName, Key, Value, Options, HTTPHeaders, config]),
    erlcloud_s3:put_object(BucketName, Key, Value, Options, HTTPHeaders, Config).

%-spec set_object_acl(string(), string(), proplists:proplist()) -> ok.
%
%set_object_acl(BucketName, Key, ACL) ->
%    set_object_acl(BucketName, Key, ACL, default_config()).

set_object_acl(BucketName, Key, ACL) ->
    io:format("~n~nmini_s3:set_object_acl(~p, ~p, ~p)", [BucketName, Key, ACL]),
    erlcloud_s3:set_object_acl(BucketName, Key, ACL).

%-spec set_object_acl(string(), string(), proplists:proplist(), config()) -> ok.
%
%set_object_acl(BucketName, Key, ACL, Config)
%  when is_list(BucketName), is_list(Key), is_list(ACL) ->
%    Id = proplists:get_value(id, proplists:get_value(owner, ACL)),
%    DisplayName = proplists:get_value(display_name, proplists:get_value(owner, ACL)),
%    ACL1 = proplists:get_value(access_control_list, ACL),
%    XML = {'AccessControlPolicy',
%           [{'Owner', [{'ID', [Id]}, {'DisplayName', [DisplayName]}]},
%            {'AccessControlList', encode_grants(ACL1)}]},
%    XMLText = list_to_binary(xmerl:export_simple([XML], xmerl_xml)),
%    s3_simple_request(Config, put, BucketName, [$/|Key], "acl", [], XMLText, []).

set_object_acl(BucketName, Key, ACL, Config) ->
    io:format("~n~nmini_s3:set_object_acl(~p, ~p, ~p, ~0p)", [BucketName, Key, ACL, config]),
    erlcloud_s3:set_object_acl(BucketName, Key, ACL, Config).

%-spec set_bucket_attribute(string(),
%                           settable_bucket_attribute_name(),
%                           'bucket_owner' | 'requester' | [any()]) -> ok.
%
%set_bucket_attribute(BucketName, AttributeName, Value) ->
%    set_bucket_attribute(BucketName, AttributeName, Value, default_config()).

set_bucket_attribute(BucketName, AttributeName, Value) ->
    io:format("~n~nmini_s3:set_bucket_attribute(~p, ~p, ~p)", [BucketName, AttributeName, Value]),
    erlcloud_s3:set_bucket_attribute(BucketName, AttributeName, Value).

%-spec set_bucket_attribute(string(), settable_bucket_attribute_name(),
%                           'bucket_owner' | 'requester' | [any()], config()) -> ok.
%
%set_bucket_attribute(BucketName, AttributeName, Value, Config)
%  when is_list(BucketName) ->
%    {Subresource, XML} =
%        case AttributeName of
%            acl ->
%                ACLXML = {'AccessControlPolicy',
%                          [{'Owner',
%                            [{'ID', [proplists:get_value(id, proplists:get_value(owner, Value))]},
%                             {'DisplayName', [proplists:get_value(display_name, proplists:get_value(owner, Value))]}]},
%                           {'AccessControlList', encode_grants(proplists:get_value(access_control_list, Value))}]},
%                {"acl", ACLXML};
%            logging ->
%                LoggingXML = {'BucketLoggingStatus',
%                              [{xmlns, ?XMLNS_S3}],
%                              case proplists:get_bool(enabled, Value) of
%                                  true ->
%                                      [{'LoggingEnabled',
%                                        [
%                                         {'TargetBucket', [proplists:get_value(target_bucket, Value)]},
%                                         {'TargetPrefix', [proplists:get_value(target_prefix, Value)]},
%                                         {'TargetGrants', encode_grants(proplists:get_value(target_grants, Value, []))}
%                                        ]
%                                       }];
%                                  false ->
%                                      []
%                              end},
%                {"logging", LoggingXML};
%            request_payment ->
%                PayerName = case Value of
%                                requester -> "Requester";
%                                bucket_owner -> "BucketOwner"
%                            end,
%                RPXML = {'RequestPaymentConfiguration', [{xmlns, ?XMLNS_S3}],
%                         [
%                          {'Payer', [PayerName]}
%                         ]
%                        },
%                {"requestPayment", RPXML};
%            versioning ->
%                Status = case proplists:get_value(status, Value) of
%                             suspended -> "Suspended";
%                             enabled -> "Enabled"
%                         end,
%                MFADelete = case proplists:get_value(mfa_delete, Value, disabled) of
%                                enabled -> "Enabled";
%                                disabled -> "Disabled"
%                            end,
%                VersioningXML = {'VersioningConfiguration', [{xmlns, ?XMLNS_S3}],
%                                 [{'Status', [Status]},
%                                  {'MfaDelete', [MFADelete]}]},
%                {"versioning", VersioningXML}
%        end,
%    POSTData = list_to_binary(xmerl:export_simple([XML], xmerl_xml)),
%    Headers = [{"content-type", "application/xml"}],
%    s3_simple_request(Config, put, BucketName, "/", Subresource, [], POSTData, Headers).

set_bucket_attribute(BucketName, AttributeName, Value, Config) ->
    io:format("~n~nmini_s3:set_bucket_attribute(~p, ~p, ~p, ~0p)", [BucketName, AttributeName, Value, config]),
    erlcloud_s3:set_bucket_attribute(BucketName, AttributeName, Value, Config).

encode_grants(Grants) ->
    [encode_grant(Grant) || Grant <- Grants].

encode_grant(Grant) ->
    Grantee = proplists:get_value(grantee, Grant),
    {'Grant',
     [{'Grantee', [{xmlns, ?XMLNS_S3}],
       [{'ID', [proplists:get_value(id, proplists:get_value(owner, Grantee))]},
        {'DisplayName', [proplists:get_value(display_name, proplists:get_value(owner, Grantee))]}]},
      {'Permission', [encode_permission(proplists:get_value(permission, Grant))]}]}.

s3_simple_request(Config, Method, Host, Path, Subresource, Params, POSTData, Headers) ->
    case s3_request(Config, Method, Host, Path,
                    Subresource, Params, POSTData, Headers) of
        {_Headers, ""} -> ok;
        {_Headers, Body} ->
            XML = element(1,xmerl_scan:string(Body)),
            case XML of
                #xmlElement{name='Error'} ->
                    ErrCode = ms3_xml:get_text("/Error/Code", XML),
                    ErrMsg = ms3_xml:get_text("/Error/Message", XML),
                    erlang:error({s3_error, ErrCode, ErrMsg});
                _ ->
                    ok
            end
    end.

s3_xml_request(Config, Method, Host, Path, Subresource, Params, POSTData, Headers) ->
    {_Headers, Body} = s3_request(Config, Method, Host, Path,
                                  Subresource, Params, POSTData, Headers),
    XML = element(1,xmerl_scan:string(Body)),
    case XML of
        #xmlElement{name='Error'} ->
            ErrCode = ms3_xml:get_text("/Error/Code", XML),
            ErrMsg = ms3_xml:get_text("/Error/Message", XML),
            erlang:error({s3_error, ErrCode, ErrMsg});
        _ ->
            XML
    end.

s3_request(Config = #config{access_key_id=AccessKey,
                            secret_access_key=SecretKey,
                            ssl_options=SslOpts},
           Method, Host, Path, Subresource, Params, POSTData, Headers) ->
io:format("~nmini_s3:s3_request -----------------"),
io:format("~nMethod: ~p",       [Method]),
io:format("~nHost: ~p",         [Host]),
io:format("~nPath: ~p",         [Path]),
io:format("~nSubresource: ~p",  [Subresource]),
io:format("~nParams: ~p",       [Params]),
io:format("~nPOSTData: ~p",     [POSTData]),
io:format("~nHeaders: ~p",      [Headers]),
    {ContentMD5, ContentType, Body} =
        case POSTData of
            {PD, CT} ->
                {base64:encode(erlang:md5(PD)), CT, PD};
            PD ->
                %% On a put/post even with an empty body we need to
                %% default to some content-type
                case Method of
                    _ when put == Method; post == Method ->
                        {"", "text/xml", PD};
                    _ ->
                        {"", "", PD}
                end
        end,
    AmzHeaders = lists:filter(fun ({"x-amz-" ++ _, V}) when
                                        V =/= undefined -> true;
                                  (_) -> false
                              end, Headers),
    Date = httpd_util:rfc1123_date(erlang:localtime()),
    EscapedPath = ms3_http:url_encode_loose(Path),
%    {_StringToSign, Authorization} =
%        make_authorization(AccessKey, SecretKey, Method,
%                           ContentMD5, ContentType,
%                           Date, AmzHeaders, Host,
%                           EscapedPath, Subresource),
    FHeaders = [Header || {_, Value} = Header <- Headers, Value =/= undefined],
%    RequestHeaders0 = [{"date", Date}, {"authorization", Authorization}|FHeaders] ++
RequestHeaders0 = FHeaders ++
        case ContentMD5 of
            "" -> [];
            _ -> [{"content-md5", binary_to_list(ContentMD5)}]
        end,
    RequestHeaders1 = case proplists:is_defined("Content-Type", RequestHeaders0) of
                          true ->
                              RequestHeaders0;
                          false ->
                              [{"Content-Type", ContentType} | RequestHeaders0]
                      end,
%    RequestURI = lists:flatten([format_s3_uri(Config, Host),
%                                EscapedPath,
%                                if_not_empty(Subresource, [$?, Subresource]),
%                                if
%                                    Params =:= [] -> "";
%                                    Subresource =:= "" -> [$?, ms3_http:make_query_string(Params)];
%                                    true -> [$&, ms3_http:make_query_string(Params)]
%                                end]),
    IbrowseOpts = [ {ssl_options, SslOpts} ],
%{Headers, _Body} = s3_request(Config, head, BucketName, [$/|Key], Subresource, [], <<>>, RequestHeaders),
[$/ | Key] = Path,
Lifetime = 300,
io:format("~nKey: ~p",              [Key]),
io:format("~nRequestHeaders1: ~p",  [RequestHeaders1]),
io:format("~nDate: ~p",             [Date]),
RequestURI = s3_url(Method, Host, Key, Lifetime, RequestHeaders1, Date, Config),
    Response = case Method of
                   get ->
                       ibrowse:send_req(RequestURI, RequestHeaders1, Method, [], IbrowseOpts);
                   delete ->
                       ibrowse:send_req(RequestURI, RequestHeaders1, Method, [], IbrowseOpts);
                   head ->
                       %% ibrowse is unable to handle HEAD request responses that are sent
                       %% with chunked transfer-encoding (why servers do this is not
                       %% clear). While we await a fix in ibrowse, forcing the HEAD request
                       %% to use HTTP 1.0 works around the problem.
                       IbrowseOpts1 = [{http_vsn, {1, 0}} | IbrowseOpts],
                       ibrowse:send_req(RequestURI, RequestHeaders1, Method, [],
                                        IbrowseOpts1);
                   _ ->
                       ibrowse:send_req(RequestURI, RequestHeaders1, Method, Body, IbrowseOpts)
               end,
io:format("~nmini_s3:s3_request END ------------------"),
    case Response of
        {ok, Status, ResponseHeaders0, ResponseBody} ->
            ResponseHeaders = canonicalize_headers(ResponseHeaders0),
            case erlang:list_to_integer(Status) of
                OKStatus when OKStatus >= 200, OKStatus =< 299 ->
                    {ResponseHeaders, ResponseBody};
                BadStatus ->
                    erlang:error({aws_error, {http_error, BadStatus,
                                              {ResponseHeaders, ResponseBody}}})
                end;
        {error, Error} ->
            erlang:error({aws_error, {socket_error, Error}})
    end.

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

%default_config() ->
%    Defaults =  envy:get(mini_s3, s3_defaults, list),
%    case proplists:is_defined(key_id, Defaults) andalso
%        proplists:is_defined(secret_access_key, Defaults) of
%        true ->
%            {key_id, Key} = proplists:lookup(key_id, Defaults),
%            {secret_access_key, AccessKey} =
%                proplists:lookup(secret_access_key, Defaults),
%            #config{access_key_id=Key, secret_access_key=AccessKey};
%        false ->
%            throw({error, missing_s3_defaults})
%    end.

default_config() ->
    #aws_config{}. 
