%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Amazon Simple Storage Service (S3)
%% Copyright 2010-2019 Chef, Inc. All Rights Reserved.
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

-module(mini_s3_signing).

-export([s3_url/6,
         s3_request/8,
         make_authorization/10,
         universaltime/0,
         make_v4_canonical_request/7]).

-export([canonicalize_headers/1,
         retrieve_header_value/2,
         make_signed_url_authorization_v2/5,
         make_signed_url_authorization_v4/5,
         make_s3_request/5 % only to silence warning  
        ]).

-export_type([config/0]).


-ifdef(TEST).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("internal.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-opaque config() :: #config{}.

-define(V4_SIGNING_ALGORITHM_NAME, "AWS4-HMAC-SHA256").
-define(S3_SCOPE_NAME, "s3"). % is there a better name for this?
-define(V4_SCOPE_TERMINATION, "aws4_request").
-define(UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD").

-define(XMLNS_S3, "http://s3.amazonaws.com/doc/2006-03-01/").


%% @doc Canonicalizes a proplist of {"Header", "Value"} pairs by
%% lower-casing all the Headers.
%%
-spec canonicalize_headers([{string() | binary() | atom(), Value::string()}]) ->
                                  [{LowerCaseHeader::string(), Value::string()}].
canonicalize_headers(Headers) ->
    [ {string:to_lower(to_string(H)), V} || {H, V} <- Headers ].


%% AWS V4 requires sorting;
%% Each header is terminated with a "\n"
make_header_string(Headers) ->
    lists:flatten([ [E, "\n"] || E <- lists:sort([ [H, $:, V] || {H,V} <- Headers]) ]).

% %
make_signed_header_list(Headers) ->
    Keys = lists:sort([string:to_lower(to_string(H)) || {H,_} <- Headers]),
    safe_join(";",Keys).

-spec to_string(atom() | binary() | string()) -> string().
to_string(A) when is_atom(A) ->
    erlang:atom_to_list(A);
to_string(B) when is_binary(B) ->
    erlang:binary_to_list(B);
to_string(S) when is_list(S) ->
    S.


%% Takes a list of string elements and joins them with nl
%% lists:join isn't avail in OTP18
safe_join(C, L) ->
    lists:foldr(fun(E,[]) ->
                        [to_string(E)];
                   (E, A) ->
                        [to_string(E), C | A]
                end,
                [],
                L).

safe_join_nl(L) ->
    safe_join("\n",L).


%% @doc Retrieves a value from a set of canonicalized headers.  The
%% given header should already be canonicalized (i.e., lower-cased).
%% Returns the value or the empty string if no such value was found.
-spec retrieve_header_value(Header::string(),
                            AllHeaders::[{Header::string(), Value::string()}]) ->
                                   string().
retrieve_header_value(Header, AllHeaders) ->
    proplists:get_value(Header, AllHeaders, "").


%%
%% Manage time
%%
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
    {{NowY, NowMo, NowD},{_,_,_}} = Now = ?MODULE:universaltime(),
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
    Now = calendar:datetime_to_gregorian_seconds(?MODULE:universaltime()),
    (Now - ?EPOCH) + TimeToLive.

%%
%% AWS V4 signing represents the expiration time differently
%%
make_start_and_expiration_time({TimeToLive, _Interval}) ->
    %% hold off on implementing rounding algorithm above for now
    %% future work round now down to interval bounds, add delta to time to live
    make_start_and_expiration_time(TimeToLive);
make_start_and_expiration_time(TimeToLive) ->
    Now = ?MODULE:universaltime(),
    {Now, TimeToLive}.

%% Abstraction of universaltime, so it can be mocked via meck
-spec universaltime() -> calendar:datetime().
universaltime() ->
    erlang:universaltime().

%% Replace with real iso8601 once I find one that still builds on R18; for now this eliminates a library dep.
make_aws_datetime({{Y,Mo,D},{H,Mi,S}}) ->
    io_lib:format("~4w~2.2.0w~2.2.0wT~2.2.0w~2.2.0w~2.2.0wZ",[Y,Mo,D,H,Mi,S]).

make_aws_date({{Y,M,D},{_,_,_}}) ->
    io_lib:format("~4w~2.2.0w~2.2.0w",[Y,M,D]).

%%
%%
%%
%%

-spec if_not_empty(string(), iolist()) -> iolist().
if_not_empty("", _V) ->
    "";
if_not_empty(_, Value) ->
    Value.

%%
%% Crypto, AWS style
%%
%%

hexencode(Data) when is_binary(Data) ->
    lists:flatten([io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Data]).

%% lowercase hex byte string of value
%% Empty string "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
-spec aws_v4_hash_payload(iolist()) -> string().
aws_v4_hash_payload(Payload) ->
    Hash = crypto:hash(sha256, iolist_to_binary(Payload)),
    hexencode(Hash).

aws_v4_hmac(Key, Data) ->
    crypto:hmac(sha256, Key, Data).

%% https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
%% secret = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY.
%% HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,"20150830"),"us-east-1"),"iam"),"aws4_request")
%% should be c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9 (but in binary)
aws_v4_signing_key(UTime, #config{secret_access_key = SecretKey, region = Region, service = Service}) ->
    KStart   = "AWS4" ++ to_string(SecretKey),
    KDate    = aws_v4_hmac(KStart, lists:flatten(make_aws_date(UTime))),
    KRegion  = aws_v4_hmac(KDate, to_string(Region)),
    KService = aws_v4_hmac(KRegion, to_string(Service)),
    KSigning = aws_v4_hmac(KService, ?V4_SCOPE_TERMINATION),
    KSigning.

aws_v4_signature(Key, StringToSign) ->
    Hmac = aws_v4_hmac(Key, StringToSign),
    hexencode(Hmac).
%%
%%
%%
-spec format_s3_uri(config(), string()) -> string().
format_s3_uri(#config{s3_url=S3Url, bucket_access_type=BAccessType}, Host) ->
    {ok,{Protocol,UserInfo,Domain,Port,_Uri,_QueryString}} =
        http_uri:parse(S3Url, [{ipv6_host_with_brackets, true}]),
    case BAccessType of
        virtual_hosted ->
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
             proplists:proplist(), config()) -> binary().
s3_url(Method, BucketName, Key, Lifetime, RawHeaders,
       Config = #config{access_key_id=AccessKey,
                        signing_version=v2})
  when is_list(BucketName), is_list(Key) ->

    Expires = erlang:integer_to_list(expiration_time(Lifetime)),

    Path = lists:flatten([$/, BucketName, $/ , Key]),
    CanonicalizedResource = ms3_http:url_encode_loose(Path),

    {_StringToSign, Signature} = make_signed_url_authorization_v2(Method, CanonicalizedResource,
                                                                                  Expires, RawHeaders, Config),

    RequestURI = iolist_to_binary([
                                   format_s3_uri(Config, ""), CanonicalizedResource,
                                   $?, "AWSAccessKeyId=", AccessKey,
                                   $&, "Expires=", Expires,
                                   $&, "Signature=", ms3_http:url_encode_loose(Signature)
                                  ]),
    RequestURI;

s3_url(Method, BucketName, Key, Lifetime, RawHeaders,
       Config = #config{signing_version = v4})
  when is_list(BucketName), is_list(Key) ->

    {UTime, UExpire} = make_start_and_expiration_time(Lifetime),

    Path = lists:flatten([$/, BucketName, $/ , Key]),
    CanonicalizedResource = ms3_http:url_encode_loose(Path),

    RequestURI = make_signed_url_authorization_v4(Method, CanonicalizedResource,
                                                  {UTime, UExpire}, RawHeaders, Config),

    RequestURI.


%% https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
make_v4_canonical_request(Method, CanonicalURI, CanonicalQueryString,
                          {_UTime, _UExpire}, RawHeaders, PayloadHexHash,
                          #config{signing_version = v4}) ->
    Headers = RawHeaders, %% TODO add date header from utime
    RequestParts = [string:to_upper(atom_to_list(Method)),          %% HTTPRequestMethod
                    CanonicalURI,                                   %% CannonicalURI
                    CanonicalQueryString,
                    make_header_string(canonicalize_headers(Headers)), %%
                    make_signed_header_list(Headers),
                    PayloadHexHash],
    StringToSign = safe_join_nl(RequestParts),
    StringToSign.

%% https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
make_v4_string_to_sign({UTime, _UExpire}, ReqHexHash, Config) ->
    StringElements = [ ?V4_SIGNING_ALGORITHM_NAME,
                       make_aws_datetime(UTime),
                       make_v4_credential_scope(UTime, Config),
                       ReqHexHash ],
    StringToSign = safe_join_nl(StringElements),
    lists:flatten(StringToSign).


%% E.g. 20150830/us-east-1/iam/aws4_request
make_v4_credential_scope(UTime,
                         #config{region = Region,
                                 service = Service,
                                 signing_version = v4}) ->
    Elements = [ make_aws_date(UTime),
                 Region,
                 Service, % Hardcoded, but that's ok
                 ?V4_SCOPE_TERMINATION],
    safe_join("/", Elements).

make_v4_credential(AccessKeyId, UTime, Service, Region) ->
    Elements = [to_string(AccessKeyId),
                make_aws_date(UTime),
                Region,
                Service,
                ?V4_SCOPE_TERMINATION],
    lists:flatten(safe_join("/", Elements)).


make_aws_v4_headers({UTime, UExpire}, RawHeaders,
                    #config{access_key_id = AccessKeyId,
                            region = Region,
                            service = Service,
                            signing_version = v4},
                    Signature) ->
    Headers0 = [
                ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
                ["X-Amz-Credential", make_v4_credential(AccessKeyId,UTime,Service,Region)],
                ["X-Amz-Date", make_aws_datetime(UTime)],
                ["X-Amz-Expires", erlang:integer_to_list(UExpire)],
                %% Signed headers comprise headers that are not part of the X-Amx-* but are in addition, e.g. host, content-type, etc
                ["X-Amz-SignedHeaders", make_signed_header_list(RawHeaders)]
            ],
    Headers1 = case Signature of
                 undefined ->
                     Headers0;
                 _ ->
                     Headers0 ++ [["X-Amz-Signature", Signature]]
             end,
    Headers1.

make_v4_query_string({UTime, UExpire}, RawHeaders,
                     #config{access_key_id = AccessKeyId,
                             region = Region,
                             signing_version = v4},
                     Signature) ->
    QueryHeaders = make_aws_v4_headers({UTime, UExpire}, RawHeaders,
                                       #config{access_key_id = AccessKeyId,
                                               region = Region,
                                               signing_version = v4},
                                       Signature),
    safe_join("&", [lists:flatten([K, $=, ms3_http:url_encode(lists:flatten(V))]) || [K,V] <- QueryHeaders]).


make_signed_url_authorization_v2(Method, CanonicalizedResource,
                                 Expires, RawHeaders,
                                 #config{secret_access_key=SecretKey}) ->
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

    Signature = base64:encode(crypto:hmac(sha, SecretKey, StringToSign)),
    {StringToSign, Signature}.

make_signed_url_authorization_v4(Method, CanonicalResource, {UTime, UExpire}, RawHeaders, #config{} = Config) ->
    Headers = canonicalize_headers(RawHeaders),
    QueryString = make_v4_query_string({UTime, UExpire}, Headers, Config, undefined),
    CanonicalRequest = make_v4_canonical_request(Method, CanonicalResource, QueryString, {UTime, UExpire}, Headers, ?UNSIGNED_PAYLOAD, Config),
    ReqHexHash = aws_v4_hash_payload(CanonicalRequest),
    StringToSign = make_v4_string_to_sign({UTime, UExpire}, ReqHexHash, Config),
    Key = aws_v4_signing_key(UTime, Config),
    Signature = aws_v4_signature(Key, StringToSign),
    CanonicalResource ++ "?" ++ make_v4_query_string({UTime, UExpire}, Headers, Config, Signature).





s3_request(Config = #config{access_key_id=AccessKey,
                            secret_access_key=SecretKey,
                            ssl_options=SslOpts},
           Method, Host, Path, Subresource, Params, POSTData, Headers) ->
    {ContentMD5, ContentType, Body} =
        case POSTData of
            {PD, CT} ->
                {base64:encode(crypto:hash(md5,PD)), CT, PD};
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
    {_StringToSign, Authorization} =
        make_authorization(AccessKey, SecretKey, Method,
                           ContentMD5, ContentType,
                           Date, AmzHeaders, Host,
                           EscapedPath, Subresource),
    FHeaders = [Header || {_, Value} = Header <- Headers, Value =/= undefined],
    RequestHeaders0 = [{"date", Date}, {"authorization", Authorization}|FHeaders] ++
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
    RequestURI = lists:flatten([format_s3_uri(Config, Host),
                                EscapedPath,
                                if_not_empty(Subresource, [$?, Subresource]),
                                if
                                    Params =:= [] -> "";
                                    Subresource =:= "" -> [$?, ms3_http:make_query_string(Params)];
                                    true -> [$&, ms3_http:make_query_string(Params)]
                                end]),
    IbrowseOpts = [ {ssl_options, SslOpts} ],
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

make_s3_request(Method, RequestURI, RequestHeaders, IbrowseOpts, Body) ->
    Response = case Method of
                   get ->
                       ibrowse:send_req(RequestURI, RequestHeaders, Method, [], IbrowseOpts);
                   delete ->
                       ibrowse:send_req(RequestURI, RequestHeaders, Method, [], IbrowseOpts);
                   head ->
                       %% ibrowse is unable to handle HEAD request responses that are sent
                       %% with chunked transfer-encoding (why servers do this is not
                       %% clear). While we await a fix in ibrowse, forcing the HEAD request
                       %% to use HTTP 1.0 works around the problem.
                       IbrowseOpts1 = [{http_vsn, {1, 0}} | IbrowseOpts],
                       ibrowse:send_req(RequestURI, RequestHeaders, Method, [],
                                        IbrowseOpts1);
                   _ ->
                       ibrowse:send_req(RequestURI, RequestHeaders, Method, Body, IbrowseOpts)
               end,
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
