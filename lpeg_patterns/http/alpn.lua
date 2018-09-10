-- RFC 7639

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"
local util = require "lpeg_patterns.util"

local Cmt = lpeg.Cmt
local Cs = lpeg.Cs
local P = lpeg.P
local R = lpeg.R

--[[ protocol-id is a percent-encoded ALPN protocol name
  - Octets in the ALPN protocol MUST NOT be percent-encoded if they
	are valid token characters except "%".
  - When using percent-encoding, uppercase hex digits MUST be used.
]]

local valid_chars = http_core.tchar - P"%"
local upper_hex = R("09", "AF")
local percent_char = P"%" * (upper_hex * upper_hex / util.read_hex) / string.char
local percent_encoded = Cmt(percent_char, function(_, _, c)
	-- check that decoded character would not have been allowed unescaped
	if not valid_chars:match(c) then
		return true, c
	end
end)
local percent_replace = Cs((valid_chars + percent_encoded)^0)

local protocol_id = percent_replace

local ALPN = http_core.comma_sep_trim(protocol_id, 1)

return {
	protocol_id = protocol_id;
	ALPN = ALPN;
}
