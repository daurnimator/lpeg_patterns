--[[
https://tools.ietf.org/html/rfc7230
https://tools.ietf.org/html/rfc7231
]]

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local uri = require "lpeg_patterns.uri"

local C = lpeg.C
local Cc = lpeg.Cc
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local Ct = lpeg.Ct
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V

-- RFC 7230 Section 3.2.3
local OWS = (core.SP + core.HTAB)^0
local RWS = (core.SP + core.HTAB)^1
local BWS = OWS

-- Analogue to RFC 7320 Section 7's ABNF extension of '#'
local function comma_sep(element, min, max)
	local sep = OWS * lpeg.P"," * OWS
	local extra = sep^1 * element
	local patt = element
	if min then
		for _=2, min do
			patt = patt * extra
		end
	else
		min = 0
	end
	if max then
		local more = max-min
		patt = patt * extra^-more
	else
		patt = patt * extra^0
	end
	if min == 0 then
		patt = patt^-1
	end
	patt = sep^0 * patt * sep^0 -- allow trailing or leading whitespace and commas
	return patt
end

-- RFC 7230 Section 2.7
local absolute_path = Cs((P"/" * uri.segment )^1)

-- RFC 7230 Section 3.2.6
local tchar = S "!#$%&'*+-.^_`|~" + core.DIGIT + core.ALPHA
local token = C(tchar^1)
local obs_text = R("\128\255")
local qdtext = core.HTAB + core.SP + P("\33") + R("\35\91", "\93\126") + obs_text
local quoted_pair = Cs(P"\\" * C(core.HTAB + core.SP + core.VCHAR + obs_text) / "%1")
local quoted_string = core.DQUOTE * Cs((qdtext + quoted_pair)^0) * core.DQUOTE

local ctext = core.HTAB + core.SP + R("\33\39", "\42\91", "\93\126") + obs_text
local comment = P { P"(" * ( ctext + quoted_pair + V(1) )^0 * P")" }

-- RFC 7230 Section 3.2
local field_name = token / string.lower -- case insensitive
local field_vchar = core.VCHAR + obs_text
local field_content = field_vchar * (( core.SP + core.HTAB )^1 * field_vchar)^-1
local obs_fold = core.CRLF * ( core.SP + core.HTAB )^1 / " "
local field_value = Cs(( field_content + obs_fold )^0)
local header_field = field_name * P":" * OWS * field_value * OWS

-- RFC 7230 Section 3.3.2
local Content_Length = core.DIGIT^1

-- RFC 7230 Section 4
local transfer_parameter = token * BWS * P"=" * BWS * ( token + quoted_string )
local transfer_extension = token / string.lower -- case insensitive
	* ( OWS * P";" * OWS * transfer_parameter )^0
local transfer_coding = transfer_extension

-- RFC 7230 Section 3.3.1
local Transfer_Encoding = comma_sep(transfer_coding, 1)

-- RFC 7230 Section 4.1.1
local chunk_ext_name = token
local chunk_ext_val = token + quoted_string
local chunk_ext = ( P";" * chunk_ext_name * ( P"=" * chunk_ext_val)^-1 )^0

-- RFC 7230 Section 4.3
local rank = (P"0" * (P"." * core.DIGIT^-3)^-1 + P"1" * ("." * (P"0")^-3)^-1) / tonumber
local t_ranking = OWS * P";" * OWS * S"qQ" * P"=" * rank -- q is case insensitive
local t_codings = transfer_coding * Cg(t_ranking)^-1
local TE = comma_sep(t_codings)

-- RFC 7230 Section 4.4
local Trailer = comma_sep(field_name, 1)

-- RFC 7230 Section 5.3
local origin_form = absolute_path * (P"?" * uri.query)^-1
local absolute_form = uri.absolute_uri
local authority_form = uri.authority
local asterisk_form = P"*"
local request_target = origin_form + absolute_form + authority_form + asterisk_form

-- RFC 7230 Section 5.4
local Host = uri.host * (P":" * uri.port)^-1

-- RFC 7230 Section 6.7
local protocol_name = token
local protocol_version = token
local protocol = protocol_name * (P"/" * protocol_version)^-1
local Upgrade = comma_sep(protocol)

-- RFC 7230 Section 5.7.1
local received_protocol = (protocol_name * P"/")^-1 * protocol_version
local pseudonym = token
local received_by = uri.host * (P":" * uri.port)^-1 + pseudonym
local Via = comma_sep(received_protocol * RWS * received_by * (RWS * comment)^-1, 1)

-- RFC 7230 Section 6.1
local connection_option = token / string.lower -- case insensitive
local Connection = comma_sep(connection_option)

-- RFC 7231 Section 3.1.1
local content_coding = token / string.lower -- case insensitive
local Content_Encoding = comma_sep(content_coding, 1)

-- RFC 7231 Section 3.1.2
local type = token / string.lower -- case insensitive
local subtype = token / string.lower -- case insensitive
local parameter = token / string.lower -- case insensitive
	* P"=" * (token + quoted_string)
local media_type = type * P"/" * subtype * (OWS * P";" * OWS * parameter)^0
local charset = token / string.lower -- case insensitive
local Content_Type = media_type

-- RFC 7231 Section 5.3.1
local qvalue = rank
local weight = t_ranking

-- RFC 7231 Section 5.3.2
local media_range = ( "*/*"
	+ (type * P"/*")
	+ (type * P"/" * subtype)
) * (OWS * ";" * OWS * parameter)^0
local accept_ext = OWS * P";" * OWS * token * (P"=" * (token + quoted_string))^-1
local accept_params = weight * (accept_ext)^0
local Accept = comma_sep(media_range * accept_params^-1)

-- RFC 7231 Section 7.1.1.1
-- Uses os.date field names
local day_name = Cg(P"Mon"*Cc(2), "wday")
	+ Cg(P"Tue"*Cc(3), "wday")
	+ Cg(P"Wed"*Cc(4), "wday")
	+ Cg(P"Thu"*Cc(5), "wday")
	+ Cg(P"Fri"*Cc(6), "wday")
	+ Cg(P"Sat"*Cc(7), "wday")
	+ Cg(P"Sun"*Cc(1), "wday")
local day = Cg(core.DIGIT * core.DIGIT / tonumber, "day")
local month = Cg(P"Jan"*Cc(1), "month")
	+ Cg(P"Feb"*Cc(2), "month")
	+ Cg(P"Mar"*Cc(3), "month")
	+ Cg(P"Apr"*Cc(4), "month")
	+ Cg(P"May"*Cc(5), "month")
	+ Cg(P"Jun"*Cc(6), "month")
	+ Cg(P"Jul"*Cc(7), "month")
	+ Cg(P"Aug"*Cc(8), "month")
	+ Cg(P"Sep"*Cc(9), "month")
	+ Cg(P"Oct"*Cc(10), "month")
	+ Cg(P"Nov"*Cc(11), "month")
	+ Cg(P"Dec"*Cc(12), "month")
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
local day_name_l = Cg(P"Monday"*Cc(2), "wday")
	+ Cg(P"Tuesday"*Cc(3), "wday")
	+ Cg(P"Wednesday"*Cc(4), "wday")
	+ Cg(P"Thursday"*Cc(5), "wday")
	+ Cg(P"Friday"*Cc(6), "wday")
	+ Cg(P"Saturday"*Cc(7), "wday")
	+ Cg(P"Sunday"*Cc(1), "wday")
local rfc850_date = Ct(day_name_l * P"," * core.SP * date2 * core.SP * time_of_day * core.SP * GMT)

local date3 = month * core.SP * (day + Cg(core.SP * core.DIGIT / tonumber, "day"))
local asctime_date = Ct(day_name * core.SP * date3 * core.SP * time_of_day * core.SP * year)
local obs_date = rfc850_date + asctime_date

local HTTP_date = IMF_fixdate + obs_date
local Date = HTTP_date

return {
	OWS = OWS;
	RWS = RWS;
	BWS = BWS;

	token = token;
	quoted_string = quoted_string;
	comment = comment;
	request_target = request_target;
	field_name = field_name;
	field_value = field_value;
	header_field = header_field;
	chunk_ext = chunk_ext;

	Connection = Connection;
	Content_Length = Content_Length;
	Host = Host;
	TE = TE;
	Trailer = Trailer;
	Transfer_Encoding = Transfer_Encoding;
	Upgrade = Upgrade;
	Via = Via;

	Accept = Accept;
	Content_Encoding = Content_Encoding;
	Content_Type = Content_Type;
	Date = Date;
}
