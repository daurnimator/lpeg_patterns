-- RFC 5988

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local http_parameters = require "lpeg_patterns.http.parameters"
local uri = require "lpeg_patterns.uri"

local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P
local S = lpeg.S

local ptokenchar = S"!#$%&'()*+-./:<=>?@[]^_`{|}~" + core.DIGIT + core.ALPHA
local ptoken = ptokenchar^1
local ext_name_star = http_parameters.parmname * P"*"
local link_extension = ext_name_star * P"=" * http_parameters.ext_value
	+ http_parameters.parmname * (P"=" * (ptoken + http_core.quoted_string))^-1
-- See https://www.rfc-editor.org/errata_search.php?rfc=5988&eid=3158
local link_param = link_extension
local link_value = Cf(Ct(P"<" * uri.uri_reference * P">") * (http_core.OWS * P";" * http_core.OWS * Cg(link_param))^0, rawset)
-- TODO: handle multiple ext_value variants...
-- e.g. server might provide one title in english, one in chinese, client should be able to pick which one to display

local Link = http_core.comma_sep_trim(link_value)

return {
	Link = Link;
}
