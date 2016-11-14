-- https://tools.ietf.org/html/rfc3987

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local uri = require "lpeg_patterns.uri"
local IPv4 = require "lpeg_patterns.IPv4"

local Cc = lpeg.Cc
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local Ct = lpeg.Ct
local Cmt = lpeg.Cmt
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S

local _M = {}

local cont = R"\128\191" -- continuation byte
local utf8 = R"\0\127" / string.byte
	+ R"\194\223" * cont / function(s)
		local c1, c2 = string.byte(s, 1, 2)
		return c1 * 64 + c2 - 12416
	end
	+ R"\224\239" * cont * cont / function(s)
		local c1, c2, c3 = string.byte(s, 1, 3)
		return (c1 * 64 + c2) * 64 + c3 - 925824
	end
	+ R"\240\244" * cont * cont * cont / function(s)
		local c1, c2, c3, c4 = string.byte(s, 1, 4)
		return ((c1 * 64 + c2) * 64 + c3) * 64 + c4 - 63447168
	end

local ucschar = Cmt(utf8, function(_, i, codepoint)
	local found
	if codepoint <= 0xD7FF then
		found = codepoint >= 0xA0
	elseif codepoint <= 0xFDCF then
		found = codepoint >= 0xF900
	elseif codepoint <= 0xFFEF then
		found = codepoint >= 0xFDF0
	elseif codepoint <= 0x1FFFD then
		found = codepoint >= 0x10000
	elseif codepoint <= 0x2FFFD then
		found = codepoint >= 0x20000
	elseif codepoint <= 0x3FFFD then
		found = codepoint >= 0x30000
	elseif codepoint <= 0x4FFFD then
		found = codepoint >= 0x40000
	elseif codepoint <= 0x5FFFD then
		found = codepoint >= 0x50000
	elseif codepoint <= 0x6FFFD then
		found = codepoint >= 0x60000
	elseif codepoint <= 0x7FFFD then
		found = codepoint >= 0x70000
	elseif codepoint <= 0x8FFFD then
		found = codepoint >= 0x80000
	elseif codepoint <= 0x9FFFD then
		found = codepoint >= 0x90000
	elseif codepoint <= 0xAFFFD then
		found = codepoint >= 0xA0000
	elseif codepoint <= 0xBFFFD then
		found = codepoint >= 0xB0000
	elseif codepoint <= 0xCFFFD then
		found = codepoint >= 0xC0000
	elseif codepoint <= 0xDFFFD then
		found = codepoint >= 0xD0000
	elseif codepoint <= 0xEFFFD then
		found = codepoint >= 0xE1000
	end
	if found then
		return true, i
	else
		return false
	end
end)

local iunreserved = core.ALPHA + core.DIGIT + S"-._~" + ucschar

local iuserinfo = Cs((iunreserved + uri.pct_encoded + uri.sub_delims + P":")^0)

-- TODO: Normalisation
local ireg_name = Cs((
	iunreserved
	+ uri.pct_encoded
	+ uri.sub_delims
)^1) + Cc(nil)
local ihost = (uri.IP_literal + IPv4.IPv4address) / tostring + ireg_name

local ipchar = iunreserved + uri.pct_encoded + uri.sub_delims + S":@"
local isegment = ipchar^0
local isegment_nz = ipchar^1
local isegment_nz_nc = (ipchar - P":")^1

local ipath_empty = Cc(nil) -- an empty path is nil instead of the empty string
local ipath_abempty = Cs((P"/" * isegment)^1) + ipath_empty
local ipath_rootless = Cs(isegment_nz * (P"/" * isegment)^0)
local ipath_noscheme = Cs(isegment_nz_nc * (P"/" * isegment)^0)
local ipath_absolute = Cs(P"/" * (isegment_nz * (P"/" * isegment)^0)^-1)

local iprivate = Cmt(utf8, function(_, i, codepoint)
	local found
	if codepoint <= 0xF8FF then
		found = codepoint >= 0xE000
	elseif codepoint <= 0xFFFFD then
		found = codepoint >= 0xF0000
	elseif codepoint <= 0x10FFFD then
		found = codepoint >= 0x100000
	end
	if found then
		return true, i
	else
		return false
	end
end)

local iquery = Cs((ipchar + iprivate + S"/?")^0)

local ifragment = Cs((ipchar + S"/?")^0)

local iauthority = (Cg(iuserinfo, "userinfo") * P"@")^-1
	* Cg(ihost, "host")
	* (P":" * Cg(uri.port, "port"))^-1

local ihier_part = P"//" * iauthority * Cg(ipath_abempty, "path")
	+ Cg(ipath_absolute + ipath_rootless + ipath_empty, "path")

_M.absolute_IRI = Ct(
	(Cg(uri.scheme, "scheme") * P":")
	* ihier_part
	* (P"?" * Cg(iquery, "query"))^-1
)

_M.IRI = Ct(
	(Cg(uri.scheme, "scheme") * P":")
	* ihier_part
	* (P"?" * Cg(iquery, "query"))^-1
	* (P"#" * Cg(ifragment, "fragment"))^-1
)

local irelative_part = P"//" * iauthority * Cg(ipath_abempty, "path")
	+ Cg(ipath_absolute + ipath_noscheme + ipath_empty, "path")
local irelative_ref = Ct(
	irelative_part
	* (P"?" * Cg(iquery, "query"))^-1
	* (P"#" * Cg(ifragment, "fragment"))^-1
)
_M.IRI_reference = _M.IRI + irelative_ref

_M.ipath = ipath_abempty + ipath_absolute + ipath_noscheme + ipath_rootless + ipath_empty

return _M
