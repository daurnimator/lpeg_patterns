-- RFC 7838
-- HTTP Alternative Services

local lpeg = require "lpeg"
local http_alpn = require "lpeg_patterns.http.alpn"
local http_core = require "lpeg_patterns.http.core"
local http_semantics = require "lpeg_patterns.http.semantics"
local uri = require "lpeg_patterns.uri"

local C = lpeg.C
local P = lpeg.P

local clear = C"clear" -- case-sensitive
local alt_authority = http_core.quoted_string -- containing [ uri_host ] ":" port
local alternative = http_alpn.protocol_id * P"=" * alt_authority
local alt_value = alternative * (http_core.OWS * P";" * http_core.OWS * http_semantics.parameter)^0
local Alt_Svc = clear + http_core.comma_sep_trim(alt_value, 1)
local Alt_Used = uri.host * (P":" * uri.port)^-1

return {
	Alt_Svc = Alt_Svc;
	Alt_Used = Alt_Used;
}
