-- RFC 6266
-- Use of the Content-Disposition Header Field in the
-- Hypertext Transfer Protocol (HTTP)

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"
local http_parameters = require "lpeg_patterns.http.parameters"

local C = lpeg.C
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P

local disp_ext_type = http_core.token / string.lower
local disposition_type = disp_ext_type
-- can't use 'token' here as we need to not include the "*" at the end
local ext_token = C((http_core.tchar-P"*"*(-http_core.tchar))^1) * P"*"
local value = http_core.token + http_core.quoted_string
local disp_ext_parm = ext_token * http_core.OWS * P"=" * http_core.OWS * http_parameters.ext_value
	+ http_core.token * http_core.OWS * P"=" * http_core.OWS * value
local disposition_parm = disp_ext_parm
local Content_Disposition = disposition_type * Cf(Ct(true) * (http_core.OWS * P";" * http_core.OWS * Cg(disposition_parm))^0, rawset)

return {
	Content_Disposition = Content_Disposition;
}
