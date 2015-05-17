-- IPv6

local tonumber = tonumber
local unpack = table.unpack or unpack

local lpeg = require "lpeg"
local P = lpeg.P
local Cc = lpeg.Cc
local Cg = lpeg.Cg

local core = require "lpeg_patterns.core"
local HEXDIG = core.HEXDIG

local IPv4address = require "lpeg_patterns.IPv4".IPv4address

local IPv6_methods = {}
local IPv6_mt = {
	__index = IPv6_methods;
}

local function new_IPv6(o1, o2, o3, o4, o5, o6, o7, o8)
	return setmetatable({o1, o2, o3, o4, o5, o6, o7, o8}, IPv6_mt)
end

function IPv6_methods:unpack()
	return self[1], self[2], self[3], self[4], self[5], self[6], self[7], self[8]
end

function IPv6_methods:binary()
	local t = {}
	for i=1, 8 do
		local lo = self[i] % 256
		t[i*2-1] = (self[i] - lo) / 256
		t[i*2] = lo
	end
	return string.char(unpack(t, 1, 16))
end

function IPv6_mt:__tostring()
	return string.format("%x:%x:%x:%x:%x:%x:%x:%x", self:unpack())
end

-- RFC 3986 Section 3.2.2
local h16 = HEXDIG * HEXDIG^-3 / function ( x ) return tonumber ( x , 16 ) end
local h16c = h16 * P":"
local ls32 = ( h16c * h16 ) + IPv4address / function ( ipv4 )
	local o1, o2, o3, o4 = ipv4:unpack()
	return o1*2^8 + o2 , o3*2^8 + o4
end
local function mh16c(n)
	local acc = P(true)
	for _=1, n do
		acc = acc * h16c
	end
	return acc
end
local function mh16(n)
	return mh16c(n-1) * h16
end
local function mcc(n)
	local t = {}
	for i=1, n do
		t[i] = 0
	end
	return P"::" * Cc(unpack(t,1,n))
end

local IPv6address = Cg(
	                      mh16c(6) * ls32
     +           mcc(1) * mh16c(5) * ls32
     +           mcc(2) * mh16c(4) * ls32
     + h16     * mcc(1) * mh16c(4) * ls32
     +           mcc(3) * mh16c(3) * ls32
     + h16     * mcc(2) * mh16c(3) * ls32
     + mh16(2) * mcc(1) * mh16c(3) * ls32
     +           mcc(4) * mh16c(2) * ls32
     + h16     * mcc(3) * mh16c(2) * ls32
     + mh16(2) * mcc(2) * mh16c(2) * ls32
     + mh16(3) * mcc(1) * mh16c(2) * ls32
     +           mcc(5) * h16c     * ls32
     + h16     * mcc(4) * h16c     * ls32
     + mh16(2) * mcc(3) * h16c     * ls32
     + mh16(3) * mcc(2) * h16c     * ls32
     + mh16(4) * mcc(1) * h16c     * ls32
     +           mcc(6)            * ls32
     + h16     * mcc(5)            * ls32
     + mh16(2) * mcc(4)            * ls32
     + mh16(3) * mcc(3)            * ls32
     + mh16(4) * mcc(2)            * ls32
     + mh16(5) * mcc(1)            * ls32
     +           mcc(7) * h16
     + h16     * mcc(6) * h16
     + mh16(2) * mcc(5) * h16
     + mh16(3) * mcc(4) * h16
     + mh16(4) * mcc(3) * h16
     + mh16(5) * mcc(2) * h16
     + mh16(6) * mcc(1) * h16
     +           mcc(8)
     + mh16(1) * mcc(7)
     + mh16(2) * mcc(6)
     + mh16(3) * mcc(5)
     + mh16(4) * mcc(4)
     + mh16(5) * mcc(3)
     + mh16(6) * mcc(2)
     + mh16(7) * mcc(1)
) / new_IPv6

return {
	IPv6_methods = IPv6_methods;
	IPv6_mt = IPv6_mt;
	IPv6address = IPv6address;
}
