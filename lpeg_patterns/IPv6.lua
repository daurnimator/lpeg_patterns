-- IPv6

local tonumber = tonumber

local lpeg = require "lpeg"
local P = lpeg.P
local Cg = lpeg.Cg

local core = require "lpeg_patterns.core"
local HEXDIG = core.HEXDIG

local IPv4address = require "lpeg_patterns.IPv4".IPv4address

local function new_IPv6 ( ... )
	-- TODO: Assemble ipv6 object
	return "[IPv6]"
end

-- RFC 3986 Section 3.2.2
local h16 = HEXDIG * HEXDIG^-3 / function ( x ) return tonumber ( x , 16 ) end
local ls32 = ( h16 * P":" * h16 ) + IPv4address / function ( ipv4 )
	local o1, o2, o3, o4 = ipv4:unpack()
	return o1*2^8 + o2 , o3*2^8 + o4
end

local IPv6address = Cg (    h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * ls32
	+                            P"::" * h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * ls32
	+ (                h16)^-1 * P"::"              * h16 * P":" * h16 * P":" * h16 * P":" * h16 * P":" * ls32
	+ ((h16*P":")^-1 * h16)^-1 * P"::"                           * h16 * P":" * h16 * P":" * h16 * P":" * ls32
	+ ((h16*P":")^-2 * h16)^-1 * P"::"                                        * h16 * P":" * h16 * P":" * ls32
	+ ((h16*P":")^-3 * h16)^-1 * P"::"                                                     * h16 * P":" * ls32
	+ ((h16*P":")^-4 * h16)^-1 * P"::"                                                                  * ls32
	+ ((h16*P":")^-5 * h16)^-1 * P"::"                                                                  * h16
	+ ((h16*P":")^-6 * h16)^-1 * P"::"
) / new_IPv6

return {
	IPv6address = IPv6address;
}
