-- WebDAV

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_conditional = require "lpeg_patterns.http.conditional"
local http_core = require "lpeg_patterns.http.core"
local uri = require "lpeg_patterns.uri"
local util = require "lpeg_patterns.util"

local case_insensitive = util.case_insensitive

local Cc = lpeg.Cc
local P = lpeg.P
local S = lpeg.S

local T_F = S"Tt" * Cc(true) + S"Ff" * Cc(false)

-- RFC 4918
local Coded_URL = P"<" * uri.absolute_uri * P">"
local extend = Coded_URL + http_core.token
local compliance_class = P"1" + P"2" + P"3" + extend
local DAV = http_core.comma_sep_trim(compliance_class)
local Depth = P"0" * Cc(0)
	+ P"1" * Cc(1)
	+ case_insensitive "infinity" * Cc(math.huge)
local Simple_ref = uri.absolute_uri + http_core.partial_uri
local Destination = Simple_ref
local State_token = Coded_URL
local Condition = (case_insensitive("not") * Cc("not"))^-1
	* http_core.OWS * (State_token + P"[" * http_conditional.entity_tag * P"]")
local List = P"(" * http_core.OWS * (Condition * http_core.OWS)^1 * P")"
local No_tag_list = List
local Resource_Tag = P"<" * Simple_ref * P">"
local Tagged_list = Resource_Tag * http_core.OWS * (List * http_core.OWS)^1
local If = (Tagged_list * http_core.OWS)^1 + (No_tag_list * http_core.OWS)^1
local Lock_Token = Coded_URL
local Overwrite = T_F
local DAVTimeOutVal = core.DIGIT^1 / tonumber
local TimeType = case_insensitive "Second-" * DAVTimeOutVal
	+ case_insensitive "Infinite" * Cc(math.huge)
local TimeOut = http_core.comma_sep_trim(TimeType)

-- RFC 5323
local DASL = http_core.comma_sep_trim(Coded_URL, 1)

-- RFC 6638
local Schedule_Reply = T_F
local Schedule_Tag = http_conditional.opaque_tag
local If_Schedule_Tag_Match = http_conditional.opaque_tag

-- RFC 7809
local CalDAV_Timezones = T_F

return {
	CalDAV_Timezones = CalDAV_Timezones;
	DASL = DASL;
	DAV = DAV;
	Depth = Depth;
	Destination = Destination;
	If = If;
	If_Schedule_Tag_Match = If_Schedule_Tag_Match;
	Lock_Token = Lock_Token;
	Overwrite = Overwrite;
	Schedule_Reply = Schedule_Reply;
	Schedule_Tag = Schedule_Tag;
	TimeOut = TimeOut;
}
