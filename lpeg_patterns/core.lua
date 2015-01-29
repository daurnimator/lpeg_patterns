-- Core Rules
-- https://tools.ietf.org/html/rfc5234#appendix-B.1

local lpeg = require "lpeg"

local P = lpeg.P
local R = lpeg.R
local S = lpeg.S

local _M = { }

_M.ALPHA = R("AZ","az")
_M.BIT   = S"01"
_M.CHAR  = R"\1\127"
_M.CRLF  = P"\r\n"
_M.CTL   = R"\0\31" + P"\127"
_M.DIGIT = R"09"
_M.HEXDIG= _M.DIGIT + S"ABCDEFabcdef"
_M.VCHAR = R"\21\126"
_M.WSP   = S" \t"

return _M
