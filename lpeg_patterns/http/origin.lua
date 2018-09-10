-- RFC 6454

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local uri = require "lpeg_patterns.uri"

local C = lpeg.C
local P = lpeg.P

-- discard captures from scheme, host, port and just get whole string
local serialized_origin = C(uri.scheme * P"://" * uri.host * (P":" * uri.port)^-1/function() end)
local origin_list = serialized_origin * (core.SP * serialized_origin)^0
local origin_list_or_null = P"null" + origin_list
local Origin = http_core.OWS * origin_list_or_null * http_core.OWS

return {
	serialized_origin = serialized_origin;
	Origin = Origin;
}
