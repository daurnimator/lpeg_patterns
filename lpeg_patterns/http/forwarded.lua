-- RFC 7239
-- Forwarded HTTP Extension

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"

local P = lpeg.P

-- RFC 7239 Section 4
local value = http_core.token + http_core.quoted_string
local forwarded_pair = http_core.token * P"=" * value
local forwarded_element = forwarded_pair^-1 * (P";" * forwarded_pair^-1)^0
local Forwarded = http_core.comma_sep_trim(forwarded_element)

return {
	Forwarded = Forwarded;
}
