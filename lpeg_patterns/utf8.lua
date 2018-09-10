-- RFC 3629 Section 4

local lpeg = require "lpeg"
local P = lpeg.P
local R = lpeg.R

local UTF8_tail = R("\128\191")
local UTF8_1 = R("\0\127")
local UTF8_2 = R("\194\223") * UTF8_tail
local UTF8_3 = P"\224" * R("\160\191") * UTF8_tail
	+ R("\225\236") * UTF8_tail * UTF8_tail
	+ P"\237" * R("\128\159") * UTF8_tail
	+ R("\238\239") * UTF8_tail * UTF8_tail
local UTF8_4 = P"\240" * R("\144\191") * UTF8_tail * UTF8_tail
    + R("\241\243") * UTF8_tail * UTF8_tail * UTF8_tail
	+ P"\244" * R("\128\143") * UTF8_tail * UTF8_tail

local UTF8_char = UTF8_1 + UTF8_2 + UTF8_3 + UTF8_4
local UTF8_octets = UTF8_char^0

return {
	UTF8_1 = UTF8_1;
	UTF8_2 = UTF8_2;
	UTF8_3 = UTF8_3;
	UTF8_4 = UTF8_4;
	UTF8_char = UTF8_char;
	UTF8_octets = UTF8_octets;
}
