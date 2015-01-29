-- IPv4

local lpeg = require "lpeg"
local P = lpeg.P
local R = lpeg.R
local Cg = lpeg.Cg

local core = require "lpeg_patterns.core"
local DIGIT = core.DIGIT

local dec_octet = (
		P"1"  * DIGIT * DIGIT
		+ P"2"  * R"04" * DIGIT
		+ P"25" * R"05"
		+ DIGIT * DIGIT^-1
	) / tonumber

local IPv4_mt = { }

function IPv4_mt:__tostring ( )
	local o1, o2, o3, o4 = self.binary:byte(1,4)
	return o1.."."..o2.."."..o3.."."..o4
end

local function new_IPv4 ( o1 , o2 , o3 , o4 )
	local binary = string.char ( o1 , o2 , o3 , o4 )
	return setmetatable ( { binary = binary } , IPv4_mt )
end

local IPv4address = Cg ( dec_octet * P"." * dec_octet * P"." * dec_octet * P"." * dec_octet ) / new_IPv4

return {
	IPv4_mt = IPv4_mt;
	IPv4address = IPv4address;
}
