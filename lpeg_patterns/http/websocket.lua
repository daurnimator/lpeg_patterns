local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"

local Cc = lpeg.Cc
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local Cmt = lpeg.Cmt
local P = lpeg.P
local S = lpeg.S

-- RFC 6455
local base64_character = core.ALPHA + core.DIGIT + S"+/"
local base64_data = base64_character * base64_character * base64_character * base64_character
local base64_padding = base64_character * base64_character * P"=="
	+ base64_character * base64_character * base64_character * P"="
local base64_value_non_empty = (base64_data^1 * base64_padding^-1) + base64_padding
local Sec_WebSocket_Accept = base64_value_non_empty
local Sec_WebSocket_Key = base64_value_non_empty
local registered_token = http_core.token
local extension_token = registered_token
local extension_param do
	local EOF = P(-1)
	local token_then_EOF = Cc(true) * http_core.token * EOF
	-- the quoted-string must be a valid token
	local quoted_token = Cmt(http_core.quoted_string, function(_, _, q)
		return token_then_EOF:match(q)
	end)
	extension_param = http_core.token * ((P"=" * (http_core.token + quoted_token)) + Cc(true))
end
local extension = extension_token * Cg(Cf(Ct(true) * (P";" * Cg(extension_param))^0, rawset), "parameters")
local extension_list = http_core.comma_sep_trim(Ct(extension))
local Sec_WebSocket_Extensions = extension_list
local Sec_WebSocket_Protocol_Client = http_core.comma_sep_trim(http_core.token)
local Sec_WebSocket_Protocol_Server = http_core.token
local NZDIGIT =  S"123456789"
-- Limited to 0-255 range, with no leading zeros
local version = (
	P"2" * (S"01234" * core.DIGIT + P"5" * S"012345")
	+ (P"1") * core.DIGIT * core.DIGIT
	+ NZDIGIT * core.DIGIT^-1
) / tonumber
local Sec_WebSocket_Version_Client = version
local Sec_WebSocket_Version_Server = http_core.comma_sep_trim(version)

return {
	Sec_WebSocket_Accept = Sec_WebSocket_Accept;
	Sec_WebSocket_Key = Sec_WebSocket_Key;
	Sec_WebSocket_Extensions = Sec_WebSocket_Extensions;
	Sec_WebSocket_Protocol_Client = Sec_WebSocket_Protocol_Client;
	Sec_WebSocket_Protocol_Server = Sec_WebSocket_Protocol_Server;
	Sec_WebSocket_Version_Client = Sec_WebSocket_Version_Client;
	Sec_WebSocket_Version_Server = Sec_WebSocket_Version_Server;
}
