%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
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

-module(ms3_http).

-export([make_query_string/1, url_encode/1, url_encode_loose/1]).

make_query_string(Params) ->
    string:join([[Key, "=", url_encode(value_to_string(Value))]
                 || {Key, Value} <- Params, Value =/= none, Value =/= undefined],
                "&").

value_to_string(Integer)
  when is_integer(Integer) ->
    integer_to_list(Integer);
value_to_string(Atom)
  when is_atom(Atom) ->
    atom_to_list(Atom);
value_to_string(Binary)
  when is_binary(Binary) ->
    Binary;
value_to_string(String)
  when is_list(String) ->
    String.

url_encode(Binary) when is_binary(Binary) ->
    url_encode(binary_to_list(Binary));
url_encode(String) ->
    url_encode(String, []).
url_encode([], Accum) ->
    lists:reverse(Accum);
url_encode([Char|String], Accum)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9;
       Char =:= $-; Char =:= $_;
       Char =:= $.; Char =:= $~ ->
    url_encode(String, [Char|Accum]);
url_encode([Char|String], Accum)
  when Char >=0, Char =< 255 ->
    url_encode(String, [hex_char(Char rem 16), hex_char(Char div 16),$%|Accum]).

url_encode_loose(Binary) when is_binary(Binary) ->
    url_encode_loose(binary_to_list(Binary));
url_encode_loose(String) ->
    url_encode_loose(String, []).
url_encode_loose([], Accum) ->
    lists:reverse(Accum);
url_encode_loose([Char|String], Accum)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9;
       Char =:= $-; Char =:= $_;
       Char =:= $.; Char =:= $~;
       Char =:= $/; Char =:= $: ->
    url_encode_loose(String, [Char|Accum]);
url_encode_loose([Char|String], Accum)
  when Char >=0, Char =< 255 ->
    url_encode_loose(String, [hex_char(Char rem 16), hex_char(Char div 16),$%|Accum]).

hex_char(C)
  when C >= 0, C =< 9 ->
    $0 + C;
hex_char(C)
  when C >= 10, C =< 15 ->
    $A + C - 10.
