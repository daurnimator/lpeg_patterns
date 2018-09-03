-- RFC 7034

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"
local util = require "lpeg_patterns.util"

local case_insensitive = util.case_insensitive
local Cc = lpeg.Cc

local X_Frame_Options = case_insensitive "deny" * Cc("deny")
	+ case_insensitive "sameorigin" * Cc("sameorigin")
	+ case_insensitive "allow-from" * http_core.RWS * require "lpeg_patterns.http.origin".serialized_origin

return {
	X_Frame_Options = X_Frame_Options;
}
