-- RFC 7233
-- Hypertext Transfer Protocol (HTTP/1.1): Range Requests

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_conditional = require "lpeg_patterns.http.conditional"
local http_core = require "lpeg_patterns.http.core"
local http_semantics = require "lpeg_patterns.http.semantics"

local C = lpeg.C
local Cc = lpeg.Cc
local P = lpeg.P

local bytes_unit = P"bytes"
local other_range_unit = http_core.token
local range_unit = C(bytes_unit) + other_range_unit

local first_byte_pos = core.DIGIT^1 / tonumber
local last_byte_pos = core.DIGIT^1 / tonumber
local byte_range_spec = first_byte_pos * P"-" * last_byte_pos^-1
local suffix_length = core.DIGIT^1 / tonumber
local suffix_byte_range_spec = Cc(nil) * P"-" * suffix_length
local byte_range_set = http_core.comma_sep(byte_range_spec + suffix_byte_range_spec, 1)
local byte_ranges_specifier = bytes_unit * P"=" * byte_range_set

-- RFC 7233 Section 2.3
local acceptable_ranges = http_core.comma_sep_trim(range_unit, 1) + P"none"
local Accept_Ranges = acceptable_ranges

-- RFC 7233 Section 3.1
local other_range_set = core.VCHAR^1
local other_ranges_specifier = other_range_unit * P"=" * other_range_set
local Range = byte_ranges_specifier + other_ranges_specifier

-- RFC 7233 Section 3.2
local If_Range = http_conditional.entity_tag + http_semantics.HTTP_date

-- RFC 7233 Section 4.2
local complete_length = core.DIGIT^1 / tonumber
local unsatisfied_range = P"*/" * complete_length
local byte_range = first_byte_pos * P"-" * last_byte_pos
local byte_range_resp = byte_range * P"/" * (complete_length + P"*")
local byte_content_range = bytes_unit * core.SP * (byte_range_resp + unsatisfied_range)
local other_range_resp = core.CHAR^0
local other_content_range = other_range_unit * core.SP * other_range_resp
local Content_Range = byte_content_range + other_content_range

return {
	Accept_Ranges = Accept_Ranges;
	Range = Range;
	If_Range = If_Range;
	Content_Range = Content_Range;
}
