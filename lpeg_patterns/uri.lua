-- URI
-- RFC 3986

local tonumber = tonumber
local strchar  = string.char

local lpeg = require "lpeg"
local P = lpeg.P
local S = lpeg.S
local C = lpeg.C
local Cc = lpeg.Cc
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local Ct = lpeg.Ct

local core = require "lpeg_patterns.core"
local ALPHA = core.ALPHA
local DIGIT = core.DIGIT
local HEXDIG = core.HEXDIG

local IPv4address = require "lpeg_patterns.IPv4".IPv4address
local IPv6address = require "lpeg_patterns.IPv6".IPv6address

local function read_hex(hex_num)
	return tonumber(hex_num, 16)
end

local _M = {}

local pct_encoded = P"%" * C ( HEXDIG * HEXDIG ) / read_hex / strchar -- 2.1
local sub_delims  = S"!$&'()*+,;=" -- 2.2
local unreserved  = ALPHA + DIGIT + S"-._~" -- 2.3

local scheme      = C ( ALPHA * ( ALPHA + DIGIT + S"+-." )^0 ) -- 3.1

local userinfo    = ( unreserved + pct_encoded + sub_delims + P":" )^0 -- 3.2.1

-- Host 3.2.2

local IPvFuture_mt = {}
function IPvFuture_mt:__tostring()
	return string.format("v%x.%s", self.version, self.string)
end
local function new_IPvFuture(version, string)
	return setmetatable({version=version, string=string}, IPvFuture_mt)
end
local IPvFuture   = P"v" * (HEXDIG^1/read_hex) * P"." * C((unreserved+sub_delims+P":")^1) / new_IPvFuture

-- RFC 6874
local ZoneID      = Cs ( (unreserved + pct_encoded )^1 )
local IPv6addrz   = IPv6address * (P"%25" * ZoneID)^-1 / function(IPv6, zoneid)
	IPv6:setzoneid(zoneid)
	return IPv6
end

local IP_literal  = P"[" * ( IPv6addrz + IPvFuture ) * P"]"
local IP_host     = ( IP_literal + IPv4address ) / tostring
local host_char   = unreserved + pct_encoded --+ sub_delims
local reg_name    = Cs ( host_char^1 ) + Cc ( nil )
local host        = IP_host + reg_name

_M.port = DIGIT^0 / tonumber -- 3.2.3

-- Path 3.3
local pchar         = unreserved + pct_encoded + sub_delims + S":@"
local path_abempty  = ( P"/" * pchar^0 )^0
local path_rootless = pchar^1 * path_abempty
local path_absolute = P"/" * path_rootless^-1
local path_noscheme = (pchar-P":")^1 * path_abempty
-- an empty path is nil instead of the empty string
local path_empty    = Cc(nil)

_M.query = Cs( ( pchar + S"/?" )^0 ) -- 3.4
_M.fragment = _M.query -- 3.5

-- Put together with named captures
local authority = ( Cg ( Cs ( userinfo ) , "userinfo" ) * P"@" )^-1
	* Cg ( host , "host" )
	* ( P":" * Cg(_M.port, "port") )^-1

local hier_part = P"//" * authority * Cg ( Cs ( path_abempty ) , "path" )
	+ Cg ( Cs ( path_absolute + path_rootless ) + path_empty , "path" )

_M.uri = Ct (
	( Cg ( scheme , "scheme" ) * P":" )
	* hier_part
	* ( P"?" * Cg(_M.query, "query"))^-1
	* ( P"#" * Cg(_M.fragment, "fragment"))^-1
)

local relative_part = P"//" * authority * Cg ( Cs ( path_abempty ) , "path" )
	+ Cg ( Cs ( path_absolute + path_noscheme ) + path_empty , "path" )

local relative_ref = Ct (
	relative_part
	* ( P"?" * Cg(_M.query, "query"))^-1
	* ( P"#" * Cg(_M.fragment, "fragment"))^-1
)
_M.uri_reference = _M.uri + relative_ref

_M.path = Cs ( path_abempty + path_absolute + path_noscheme + path_rootless ) + path_empty

-- Create a slightly more sane host pattern
-- scheme is optional
-- the "//" isn't required
	-- if missing, the host needs to at least have a "." and end in two alpha characters
-- an authority is always required
local hostsegment = (host_char-P".")^1
local dns_entry   = Cs ( ( hostsegment * P"." )^1 * ALPHA^2 )
local sane_host   = IP_host + dns_entry
local sane_authority = ( Cg ( Cs ( userinfo ) , "userinfo" ) * P"@" )^-1
	* Cg ( sane_host , "host" )
	* ( P":" * Cg(_M.port, "port") )^-1
local sane_hier_part = (P"//")^-1 * sane_authority * Cg ( Cs ( path_absolute ) + path_empty , "path" )
_M.sane_uri = Ct (
	( Cg ( scheme , "scheme" ) * P":" )^-1
	* sane_hier_part
	* ( P"?" * Cg(_M.query, "query"))^-1
	* ( P"#" * Cg(_M.fragment, "fragment"))^-1
)

return _M
