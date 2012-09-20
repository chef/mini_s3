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

-module(ms3_xml).

-export([decode/2, get_text/2]).

-include_lib("xmerl/include/xmerl.hrl").

decode(Values, Node) ->
    lists:reverse(lists:foldl(fun ({Name, XPath, Type},
                                   Output) ->
                                      case get_value(XPath, Type, Node) of
                                          undefined -> Output;
                                          Value -> [{Name, Value} | Output]
                                      end
                              end,
                              [], Values)).

get_value(XPath, text, Node) ->
    get_text(XPath, Node);
get_value(XPath, optional_text, Node) ->
    get_text(XPath, Node, undefined);
get_value(XPath, integer, Node) ->
    get_integer(XPath, Node);
get_value(XPath, optional_integer, Node) ->
    case get_text(XPath, Node, undefined) of
        undefined ->
            undefined;
        Text ->
            list_to_integer(Text)
    end;
get_value(XPath, float, Node) ->
    get_float(XPath, Node);
get_value(XPath, time, Node) ->
    get_time(XPath, Node);
get_value(XPath, list, Node) ->
    get_list(XPath, Node);
get_value(XPath, boolean, Node) ->
    get_bool(XPath, Node);
get_value(XPath, optional_boolean, Node) ->
    case get_text(XPath, Node, undefined) of
        undefined ->
            undefined;
        "true" ->
            true;
        _ ->
            false
    end;
get_value(XPath, present, Node) ->
    xmerl_xpath:string(XPath, Node) =/= [];
get_value(_XPath, xml, Node) ->
    Node;
get_value(XPath, Fun, Node)
  when is_function(Fun, 1) ->
    Fun(xmerl_xpath:string(XPath, Node));
get_value(XPath, {single, Fun}, Node)
  when is_function(Fun, 1) ->
    case xmerl_xpath:string(XPath, Node) of
        [] -> undefined;
        [SubNode] -> Fun(SubNode)
    end;
get_value(XPath, {single, List}, Node)
  when is_list(List) ->
    case xmerl_xpath:string(XPath, Node) of
        [] -> undefined;
        [SubNode] -> decode(List, SubNode)
    end;
get_value(XPath, {value, Fun}, Node)
  when is_function(Fun, 1) ->
    Fun(get_text(XPath, Node));
get_value(XPath, List, Node)
  when is_list(List) ->
    [decode(List, SubNode)
     || SubNode <- xmerl_xpath:string(XPath, Node)].

get_float(XPath, Node) ->
    list_to_float(get_text(XPath, Node)).

get_text(#xmlText{value = Value}) -> Value;
get_text(#xmlElement{content = Content}) ->
    lists:flatten([get_text(Node) || Node <- Content]).

get_text(XPath, Doc) -> get_text(XPath, Doc, "").

get_text({XPath, AttrName}, Doc, Default) ->
    case xmerl_xpath:string(XPath ++ "/@" ++ AttrName, Doc)
    of
        [] -> Default;
        [#xmlAttribute{value = Value} | _] -> Value
    end;
get_text(XPath, Doc, Default) ->
    case xmerl_xpath:string(XPath ++ "/text()", Doc) of
        [] -> Default;
        TextNodes ->
            lists:flatten([Node#xmlText.value || Node <- TextNodes])
    end.

get_list(XPath, Doc) ->
    [get_text(Node)
     || Node <- xmerl_xpath:string(XPath, Doc)].

get_integer(XPath, Doc) ->
    get_integer(XPath, Doc, 0).

get_integer(XPath, Doc, Default) ->
    case get_text(XPath, Doc) of
        "" ->
            Default;
        Text ->
            list_to_integer(Text)
    end.

get_bool(XPath, Doc) ->
    case get_text(XPath, Doc, "false") of
        "true" ->
            true;
        _ ->
            false
    end.

get_time(XPath, Doc) ->
    case get_text(XPath, Doc, undefined) of
        undefined ->
            undefined;
        Time ->
            parse_time(Time)
    end.

parse_time(String) ->
    case re:run(String,
                "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2})"
                ":(\\d{2})(?:\\.\\d+)?Z",
                [{capture, all_but_first, list}])
    of
        {match, [Yr, Mo, Da, H, M, S]} ->
            {{list_to_integer(Yr), list_to_integer(Mo),
              list_to_integer(Da)},
             {list_to_integer(H), list_to_integer(M),
              list_to_integer(S)}};
        nomatch -> error
    end.
