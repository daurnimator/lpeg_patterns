-- RFC 7232
-- Hypertext Transfer Protocol (HTTP/1.1): Conditional Requests

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local http_semantics = require "lpeg_patterns.http.semantics"

local C = lpeg.C
local Cc = lpeg.Cc
local Cg = lpeg.Cg
local P = lpeg.P
local R = lpeg.R

-- RFC 7232 Section 2.2
local Last_Modified = http_semantics.HTTP_date

-- RFC 7232 Section 2.3
local weak = P"W/" -- case sensitive
local etagc = P"\33" + R"\35\115" + http_core.obs_text
local opaque_tag = core.DQUOTE * etagc^0 * core.DQUOTE
local entity_tag = Cg(weak*Cc(true) + Cc(false), "weak") * C(opaque_tag)
local ETag = entity_tag

-- RFC 7232 Section 3.1
local If_Match = P"*" + http_core.comma_sep(entity_tag, 1)

-- RFC 7232 Section 3.2
local If_None_Match = P"*" + http_core.comma_sep(entity_tag, 1)

-- RFC 7232 Section 3.3
local If_Modified_Since = http_semantics.HTTP_date

-- RFC 7232 Section 3.4
local If_Unmodified_Since = http_semantics.HTTP_date

return {
	entity_tag = entity_tag;
	opaque_tag = opaque_tag;

	Last_Modified = Last_Modified;
	ETag = ETag;
	If_Match = If_Match;
	If_None_Match = If_None_Match;
	If_Modified_Since = If_Modified_Since;
	If_Unmodified_Since = If_Unmodified_Since;
}
