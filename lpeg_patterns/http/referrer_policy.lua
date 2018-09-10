-- https://www.w3.org/TR/referrer-policy/#referrer-policy-header

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"

local C = lpeg.C

local policy_token = C"no-referrer"
	+ C"no-referrer-when-downgrade"
	+ C"strict-origin"
	+ C"strict-origin-when-cross-origin"
	+ C"same-origin"
	+ C"origin"
	+ C"origin-when-cross-origin"
	+ C"unsafe-url"
local Referrer_Policy = http_core.comma_sep_trim(policy_token, 1)

return {
	Referrer_Policy = Referrer_Policy;
}
