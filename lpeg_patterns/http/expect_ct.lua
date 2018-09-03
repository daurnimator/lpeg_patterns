-- https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-06#section-2.1

local http_core = require "lpeg_patterns.http.core"
local http_utils = require "lpeg_patterns.http.util"

local expect_ct_directive = http_utils.directive
local Expect_CT = http_utils.no_dup(http_core.comma_sep_trim(expect_ct_directive))

return {
	Expect_CT = Expect_CT;
}
