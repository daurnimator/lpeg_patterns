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
local IPvFuture   = C ( P"v" * HEXDIG^1 * P"." * ( unreserved + sub_delims + P":" )^1 )
local IP_literal  = P"[" * ( IPv6address + IPvFuture ) * P"]"
local IP_host     = ( IP_literal + IPv4address ) / tostring
local host_char   = unreserved + pct_encoded --+ sub_delims
local reg_name    = Cs ( host_char^1 ) + Cc ( nil )
local host        = IP_host + reg_name
-- Create a slightly more sane host pattern
local hostsegment = (host_char-P".")^1
local dns_entry   = Cs ( ( hostsegment * P"." )^1 * ALPHA^2 )
local sane_host   = IP_host + dns_entry

local port        = DIGIT^0 / tonumber -- 3.2.3

-- Path 3.3
local pchar         = unreserved + pct_encoded + sub_delims + S":@"
local path_abempty  = ( P"/" * pchar^0 )^0
local path_rootless = pchar^1 * path_abempty
local path_absolute = P"/" * path_rootless^-1
local path_noscheme = (pchar-P":")^1 * path_abempty

local query = C ( ( pchar + S"/?" )^0 ) -- 3.4
local fragment = query -- 3.5

_M.uri = Ct (
	( Cg ( scheme , "scheme" ) * P"://" )^-1
	-- authority
		* ( Cg ( Cs ( userinfo ) , "userinfo" ) * P"@" )^-1
		* Cg ( host , "host" )
		* ( P":" * Cg ( port , "port" ) )^-1
	* Cg ( Cs ( path_absolute ) + Cc(nil) , "path" )
	* ( P"?" * Cg ( Cs ( query ) , "query" ) )^-1
	* ( P"#" * Cg ( Cs ( fragment ) , "fragment" ) )^-1
)
_M.sane_uri = Ct (
	( Cg ( scheme , "scheme" ) * P"://" )^-1
	-- authority
		* ( Cg ( Cs ( userinfo ) , "userinfo" ) * P"@" )^-1
		* Cg ( sane_host , "host" )
		* ( P":" * Cg ( port , "port" ) )^-1
	* Cg ( Cs ( path_absolute ) + Cc(nil) , "path" )
	* ( P"?" * Cg ( Cs ( query ) , "query" ) )^-1
	* ( P"#" * Cg ( Cs ( fragment ) , "fragment" ) )^-1
)

return _M
