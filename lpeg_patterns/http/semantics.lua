-- RFC 7231
-- Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local email = require "lpeg_patterns.email"
local language = require "lpeg_patterns.language"
local uri = require "lpeg_patterns.uri"

local Cc = lpeg.Cc
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P
local S = lpeg.S


-- RFC 7231 Section 3.1.1
local content_coding = http_core.token / string.lower -- case insensitive
local Content_Encoding = http_core.comma_sep_trim(content_coding, 1)

-- RFC 7231 Section 3.1.2
local type = http_core.token / string.lower -- case insensitive
local subtype = http_core.token / string.lower -- case insensitive
local parameter = http_core.token / string.lower -- case insensitive
	* P"=" * (http_core.token + http_core.quoted_string)
local media_type = Cg(type, "type") * P"/" * Cg(subtype, "subtype")
	* Cg(Cf(Ct(true) * (http_core.OWS * P";" * http_core.OWS * Cg(parameter))^0, rawset), "parameters")
local charset = http_core.token / string.lower -- case insensitive
local Content_Type = Ct(media_type)

-- RFC 7231 Section 3.1.3
local Content_Language = http_core.comma_sep_trim(language.Language_Tag, 1)

-- RFC 7231 Section 3.1.4.2
local Content_Location = uri.absolute_uri + http_core.partial_uri

-- RFC 7231 Section 5.1.1
local Expect = P"100-"*S"cC"*S"oO"*S"nN"*S"tT"*S"iI"*S"nN"*S"uU"*S"eE" * Cc("100-continue")

-- RFC 7231 Section 5.1.2
local Max_Forwards = core.DIGIT^1 / tonumber

-- RFC 7231 Section 5.3.1
-- local qvalue = http_core.rank -- luacheck: ignore 211
local weight = http_core.t_ranking

-- RFC 7231 Section 5.3.2
local media_range = (P"*/*"
	+ (Cg(type, "type") * P"/*")
	+ (Cg(type, "type") * P"/" * Cg(subtype, "subtype"))
) * Cg(Cf(Ct(true) * (http_core.OWS * ";" * http_core.OWS * Cg(parameter) - weight)^0, rawset), "parameters")
local accept_ext = http_core.OWS * P";" * http_core.OWS * http_core.token * (P"=" * (http_core.token + http_core.quoted_string))^-1
local accept_params = Cg(weight, "q") * Cg(Cf(Ct(true) * Cg(accept_ext)^0, rawset), "extensions")
local Accept = http_core.comma_sep_trim(Ct(media_range * (accept_params+Cg(Ct(true), "extensions"))))

-- RFC 7231 Section 5.3.3
local Accept_Charset = http_core.comma_sep_trim((charset + P"*") * weight^-1, 1)

-- RFC 7231 Section 5.3.4
local codings = content_coding + "*"
local Accept_Encoding = http_core.comma_sep_trim(codings * weight^-1)

-- RFC 4647 Section 2.1
local alphanum = core.ALPHA + core.DIGIT
local language_range = (core.ALPHA * core.ALPHA^-7 * (P"-" * alphanum * alphanum^-7)^0) + P"*"
-- RFC 7231 Section 5.3.5
local Accept_Language = http_core.comma_sep_trim(language_range * weight^-1, 1)

-- RFC 7231 Section 5.5.1
local From = email.mailbox

-- RFC 7231 Section 5.5.2
local Referer = uri.absolute_uri + http_core.partial_uri

-- RFC 7231 Section 5.5.3
local product_version = http_core.token
local product = http_core.token * (P"/" * product_version)^-1
local User_Agent = product * (http_core.RWS * (product + http_core.comment))^0

-- RFC 7231 Section 7.1.1.1
-- Uses os.date field names
local day_name = Cg(P"Mon"*Cc(2)
	+ P"Tue"*Cc(3)
	+ P"Wed"*Cc(4)
	+ P"Thu"*Cc(5)
	+ P"Fri"*Cc(6)
	+ P"Sat"*Cc(7)
	+ P"Sun"*Cc(1), "wday")
local day = Cg(core.DIGIT * core.DIGIT / tonumber, "day")
local month = Cg(P"Jan"*Cc(1)
	+ P"Feb"*Cc(2)
	+ P"Mar"*Cc(3)
	+ P"Apr"*Cc(4)
	+ P"May"*Cc(5)
	+ P"Jun"*Cc(6)
	+ P"Jul"*Cc(7)
	+ P"Aug"*Cc(8)
	+ P"Sep"*Cc(9)
	+ P"Oct"*Cc(10)
	+ P"Nov"*Cc(11)
	+ P"Dec"*Cc(12), "month")
local year = Cg(core.DIGIT * core.DIGIT * core.DIGIT * core.DIGIT / tonumber, "year")
local date1 = day * core.SP * month * core.SP * year

local GMT = P"GMT"

local minute = Cg(core.DIGIT * core.DIGIT / tonumber, "min")
local second = Cg(core.DIGIT * core.DIGIT / tonumber, "sec")
local hour = Cg(core.DIGIT * core.DIGIT / tonumber, "hour")
-- XXX only match 00:00:00 - 23:59:60 (leap second)?

local time_of_day = hour * P":" * minute * P":" * second
local IMF_fixdate = Ct(day_name * P"," * core.SP * date1 * core.SP * time_of_day * core.SP * GMT)

local date2 do
	local year_barrier = 70
	local twodayyear = Cg(core.DIGIT * core.DIGIT / function(y)
		y = tonumber(y, 10)
		if y < year_barrier then
			return 2000+y
		else
			return 1900+y
		end
	end, "year")
	date2 = day * P"-" * month * P"-" * twodayyear
end
local day_name_l = Cg(P"Monday"*Cc(2)
	+ P"Tuesday"*Cc(3)
	+ P"Wednesday"*Cc(4)
	+ P"Thursday"*Cc(5)
	+ P"Friday"*Cc(6)
	+ P"Saturday"*Cc(7)
	+ P"Sunday"*Cc(1), "wday")
local rfc850_date = Ct(day_name_l * P"," * core.SP * date2 * core.SP * time_of_day * core.SP * GMT)

local date3 = month * core.SP * (day + Cg(core.SP * core.DIGIT / tonumber, "day"))
local asctime_date = Ct(day_name * core.SP * date3 * core.SP * time_of_day * core.SP * year)
local obs_date = rfc850_date + asctime_date

local HTTP_date = IMF_fixdate + obs_date
local Date = HTTP_date

-- RFC 7231 Section 7.1.2
local Location = uri.uri_reference

-- RFC 7231 Section 7.1.3
local delay_seconds = core.DIGIT^1 / tonumber
local Retry_After = HTTP_date + delay_seconds

-- RFC 7231 Section 7.1.4
local Vary = P"*" + http_core.comma_sep(http_core.field_name, 1)

-- RFC 7231 Section 7.4.1
local Allow = http_core.comma_sep_trim(http_core.method)

-- RFC 7231 Section 7.4.2
local Server = product * (http_core.RWS * (product + http_core.comment))^0

return {
	HTTP_date = HTTP_date;
	IMF_fixdate = IMF_fixdate;
	media_type = media_type;
	parameter = parameter;

	Accept = Accept;
	Accept_Charset = Accept_Charset;
	Accept_Encoding = Accept_Encoding;
	Accept_Language = Accept_Language;
	Allow = Allow;
	Content_Encoding = Content_Encoding;
	Content_Language = Content_Language;
	Content_Location = Content_Location;
	Content_Type = Content_Type;
	Date = Date;
	Expect = Expect;
	From = From;
	Location = Location;
	Max_Forwards = Max_Forwards;
	Referer = Referer;
	Retry_After = Retry_After;
	Server = Server;
	User_Agent = User_Agent;
	Vary = Vary;
}
