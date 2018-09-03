-- RFC 6797

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"
local http_utils = require "lpeg_patterns.http.util"

local P = lpeg.P

local Strict_Transport_Security = http_utils.no_dup(http_utils.directive^-1 * (http_core.OWS * P";" * http_core.OWS * http_utils.directive^-1)^0)

return {
	Strict_Transport_Security = Strict_Transport_Security;
}
