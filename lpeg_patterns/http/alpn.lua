-- RFC 7639
local http_core = require "lpeg_patterns.http.core"

local protocol_id = http_core.token
local ALPN = http_core.comma_sep_trim(protocol_id, 1)

return {
	protocol_id = protocol_id;
	ALPN = ALPN;
}
