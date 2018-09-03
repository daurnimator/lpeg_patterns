-- RFC 6265

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"

local C = lpeg.C
local Cc = lpeg.Cc
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S

local cookie_name = http_core.token
local cookie_octet = S"!" + R("\35\43", "\45\58", "\60\91", "\93\126")
local cookie_value = core.DQUOTE * C(cookie_octet^0) * core.DQUOTE + C(cookie_octet^0)
local cookie_pair = cookie_name * http_core.BWS * P"=" * http_core.BWS * cookie_value * http_core.BWS

local ext_char = core.CHAR - core.CTL - S";"
ext_char = ext_char - core.WSP + core.WSP * #(core.WSP^0 * ext_char) -- No trailing whitespace
-- Complexity is to make sure whitespace before an `=` isn't captured
local extension_av = ((ext_char - S"=" - core.WSP) + core.WSP^1 * #(1-S"="))^0 / string.lower
		* http_core.BWS * P"=" * http_core.BWS * C(ext_char^0)
	+ (ext_char)^0 / string.lower * Cc(true)
local cookie_av = extension_av
local set_cookie_string = cookie_pair * Cf(Ct(true) * (P";" * http_core.OWS * Cg(cookie_av))^0, rawset)
local Set_Cookie = set_cookie_string

local cookie_string = Cf(Ct(true) * Cg(cookie_pair) * (P";" * http_core.OWS * Cg(cookie_pair))^0, rawset)
local Cookie = cookie_string

return {
	Cookie = Cookie;
	Set_Cookie = Set_Cookie;
}
