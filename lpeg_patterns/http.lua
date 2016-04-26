--[[
https://tools.ietf.org/html/rfc7230
https://tools.ietf.org/html/rfc7231
]]

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local uri = require "lpeg_patterns.uri"

local C = lpeg.C
local Cc = lpeg.Cc
local Cf = lpeg.Cf
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

-- RFC 6454
local serialized_origin = uri.scheme * P"://" * uri.host * (P":" * uri.port)
local origin_list = serialized_origin * (core.SP * serialized_origin)^0
local origin_list_or_null = P"null" + origin_list
local Origin = OWS * origin_list_or_null * OWS

-- Analogue to RFC 7320 Section 7's ABNF extension of '#'
local comma_sep do
	local sep = OWS * lpeg.P "," * OWS
	local optional_sep = (lpeg.P"," + core.SP + core.HTAB)^0
	comma_sep = function(element, min, max)
		local extra = sep * optional_sep * element
		local patt = element
		if min then
			for _=2, min do
				patt = patt * extra
			end
		else
			min = 0
			patt = patt^-1
		end
		if max then
			local more = max-min-1
			patt = patt * extra^-more
		else
			patt = patt * extra^0
		end
		patt = optional_sep * patt * optional_sep -- allow leading + trailing
		return patt
	end
end

-- RFC 7230 Section 2.6
local HTTP_name = P"HTTP"
local HTTP_version = HTTP_name * P"/" * (core.DIGIT * P"." * core.DIGIT / tonumber)

-- RFC 7230 Section 2.7
local absolute_path = (P"/" * uri.segment )^1
local partial_uri = Ct(uri.relative_part * (P"?" * uri.query)^-1)

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
-- field_value is not correct, see Errata: https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4189
local field_value = Cs((field_content + obs_fold)^0)
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
local origin_form = Cs(absolute_path * (P"?" * uri.query)^-1)
local absolute_form = uri.absolute_uri
local authority_form = uri.authority
local asterisk_form = C"*"
local request_target = asterisk_form + origin_form + absolute_form + authority_form

-- RFC 7230 Section 3.1.1
local method = token
local request_line = method * core.SP * request_target * core.SP * HTTP_version * core.CRLF

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
local media_type = Cg(type, "type") * P"/" * Cg(subtype, "subtype")
	* Cg(Cf(Ct(true) * (OWS * P";" * OWS * Cg(parameter))^0, rawset), "parameters")
local charset = token / string.lower -- case insensitive
local Content_Type = Ct(media_type)

-- RFC 7231 Section 3.1.4.2
local Content_Location = uri.absolute_uri + partial_uri

-- RFC 7231 Section 5.1.1
local Expect = P"100-"*S"cC"*S"oO"*S"nN"*S"tT"*S"iI"*S"nN"*S"uU"*S"eE" * Cc("100-continue")

-- RFC 7231 Section 5.1.2
local Max_Forwards = core.DIGIT^1 / tonumber

-- RFC 7231 Section 5.3.1
local qvalue = rank -- luacheck: ignore 211
local weight = t_ranking

-- RFC 7231 Section 5.3.2
local media_range = (P"*/*"
	+ (Cg(type, "type") * P"/*")
	+ (Cg(type, "type") * P"/" * Cg(subtype, "subtype"))
) * Cg(Cf(Ct(true) * (OWS * ";" * OWS * Cg(parameter) - weight)^0, rawset), "parameters")
local accept_ext = OWS * P";" * OWS * token * (P"=" * (token + quoted_string))^-1
local accept_params = Cg(weight, "q") * Cg(Cf(Ct(true) * Cg(accept_ext)^0, rawset), "extensions")
local Accept = comma_sep(Ct(media_range * (accept_params+Cg(Ct(true), "extensions"))))

-- RFC 7231 Section 5.3.3
local Accept_Charset = comma_sep((charset + P"*") * weight^-1, 1)

-- RFC 7231 Section 5.3.4
local codings = content_coding + "*"
local Accept_Encoding = comma_sep(codings * weight^-1)

-- RFC 4647 Section 2.1
local alphanum = core.ALPHA + core.DIGIT
local language_range = (core.ALPHA * core.ALPHA^-7 * (P"-" * alphanum * alphanum^-7)^0) + P"*"
-- RFC 7231 Section 5.3.5
local Accept_Language = comma_sep(language_range * weight^-1, 1 )

-- RFC 7231 Section 5.5.2
local Referer = uri.absolute_uri + partial_uri

-- RFC 7231 Section 5.5.3
local product_version = token
local product = token * (P"/" * product_version)^-1
local User_Agent = product * (RWS * (product + comment))^0

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
local Vary = P"*" + comma_sep(field_name, 1)

-- RFC 7231 Section 7.4.1
local Allow = comma_sep(method)

-- RFC 7231 Section 7.4.2
local Server = product * (RWS * (product + comment))^0

-- RFC 7232 Section 2.2
local Last_Modified = HTTP_date

-- RFC 7232 Section 2.3
local weak = P"W/"
local etagc = P"\33" + R"\35\115" + obs_text
local opaque_tag = core.DQUOTE * etagc^0 * core.DQUOTE
local entity_tag = weak^-1 * opaque_tag
local ETag = entity_tag

-- RFC 7232 Section 3.1
local If_Match = P"*" + comma_sep(entity_tag, 1)

-- RFC 7232 Section 3.2
local If_None_Match = P"*" + comma_sep(entity_tag, 1)

-- RFC 7232 Section 3.3
local If_Modified_Since = HTTP_date

-- RFC 7232 Section 3.4
local If_Unmodified_Since = HTTP_date

-- RFC 7233
local bytes_unit = P"bytes"
local other_range_unit = token
local range_unit = C(bytes_unit) + other_range_unit

local first_byte_pos = core.DIGIT^1 / tonumber
local last_byte_pos = core.DIGIT^1 / tonumber
local byte_range_spec = first_byte_pos * P"-" * last_byte_pos^-1
local suffix_length = core.DIGIT^1 / tonumber
local suffix_byte_range_spec = Cc(nil) * P"-" * suffix_length
local byte_range_set = comma_sep(byte_range_spec + suffix_byte_range_spec, 1)
local byte_ranges_specifier = bytes_unit * P"=" * byte_range_set

-- RFC 7233 Section 2.3
local acceptable_ranges = comma_sep(range_unit, 1) + P"none"
local Accept_Ranges = acceptable_ranges

-- RFC 7233 Section 3.1
local other_range_set = core.VCHAR^1
local other_ranges_specifier = other_range_unit * P"=" * other_range_set
local Range = byte_ranges_specifier + other_ranges_specifier

-- RFC 7233 Section 3.2
local If_Range = entity_tag + HTTP_date

-- RFC 7233 Section 4.2
local complete_length = core.DIGIT^1 / tonumber
local unsatisfied_range = P"*/" * complete_length
local byte_range = first_byte_pos * P"-" * last_byte_pos
local byte_range_resp = byte_range * P"/" * (complete_length + P"*")
local byte_content_range = bytes_unit * core.SP * (byte_range_resp + unsatisfied_range)
local other_range_resp = core.CHAR^0
local other_content_range = other_range_unit * core.SP * other_range_resp
local Content_Range = byte_content_range + other_content_range

-- RFC 7234 Section 1.2.1
local delta_seconds = core.DIGIT^1 / tonumber

-- RFC 7234 Section 5.1
local Age = delta_seconds

-- RFC 7234 Section 5.2
local cache_directive = token * (P"=" * (token + quoted_string))^-1
local Cache_Control = comma_sep(cache_directive, 1)

-- RFC 7234 Section 5.3
local Expires = HTTP_date

-- RFC 7234 Section 5.4
local extension_pragma = token * (P"=" * (token + quoted_string))^-1
local pragma_directive = "no_cache" + extension_pragma
local Pragma = comma_sep(pragma_directive, 1)

-- RFC 7234 Section 5.5
local warn_code = core.DIGIT * core.DIGIT * core.DIGIT
local warn_agent = (uri.host * (P":" * uri.port)^-1) + pseudonym
local warn_text = quoted_string
local warn_date = core.DQUOTE * HTTP_date * core.DQUOTE
local warning_value = warn_code * core.SP * warn_agent * core.SP * warn_text * (core.SP * warn_date)^-1
local Warning = comma_sep(warning_value, 1)

-- RFC 7235 Section 2
local auth_scheme = token
local auth_param = token * BWS * P"=" * BWS * (token + quoted_string)
local token68 = (core.ALPHA + core.DIGIT + P"-" + P"." + P"_" + P"~" + P"+" + P"/" )^1 * (P"=")^0
local challenge = auth_scheme * (core.SP^1 * (token68 + comma_sep(auth_param)))^-1
local credentials = auth_scheme * (core.SP^1 * (token68 + comma_sep(auth_param)))^-1

-- RFC 7235 Section 4
local WWW_Authenticate = comma_sep(challenge, 1)
local Authorization = credentials
local Proxy_Authenticate = comma_sep(challenge, 1)
local Proxy_Authorization = credentials

-- RFC 7239 Section 4
local value = token + quoted_string
local forwarded_pair = token * P"=" * value
local forwarded_element = forwarded_pair^-1 * (P";" * forwarded_pair^-1)^0
local Forwarded = comma_sep(forwarded_element)

-- RFC 7486
local Hobareg = C"regok" + C"reginwork"

-- RFC 7615
local Authentication_Info = comma_sep(auth_param)
local Proxy_Authentication_Info = comma_sep(auth_param)

-- RFC 7639
local protocol_id = token
local ALPN = comma_sep(protocol_id, 1)

-- RFC 7809
local CalDAV_Timezones = P"T" + P"F"

-- RFC 7838
local clear = C"clear" -- case-sensitive
local alt_authority = quoted_string -- containing [ uri_host ] ":" port
local alternative = protocol_id * P"=" * alt_authority
local alt_value = alternative * (OWS * P";" * OWS * parameter)^0
local Alt_Svc = clear + comma_sep(alt_value, 1)
local Alt_Used = uri.host * (P":" * uri.port)^-1

return {
	OWS = OWS;
	RWS = RWS;
	BWS = BWS;

	token = token;
	quoted_string = quoted_string;
	comment = comment;
	request_target = request_target;
	request_line = request_line;
	field_name = field_name;
	field_value = field_value;
	header_field = header_field;
	chunk_ext = chunk_ext;

	Origin = Origin;

	Connection = Connection;
	Content_Length = Content_Length;
	Host = Host;
	TE = TE;
	Trailer = Trailer;
	Transfer_Encoding = Transfer_Encoding;
	Upgrade = Upgrade;
	Via = Via;

	Accept = Accept;
	Accept_Charset = Accept_Charset;
	Accept_Encoding = Accept_Encoding;
	Accept_Language = Accept_Language;
	Allow = Allow;
	Content_Encoding = Content_Encoding;
	Content_Location = Content_Location;
	Content_Type = Content_Type;
	Date = Date;
	Expect = Expect;
	Location = Location;
	Max_Forwards = Max_Forwards;
	Referer = Referer;
	Retry_After = Retry_After;
	Server = Server;
	User_Agent = User_Agent;
	Vary = Vary;

	Last_Modified = Last_Modified;
	ETag = ETag;
	If_Match = If_Match;
	If_None_Match = If_None_Match;
	If_Modified_Since = If_Modified_Since;
	If_Unmodified_Since = If_Unmodified_Since;

	Accept_Ranges = Accept_Ranges;
	If_Range = If_Range;
	Content_Range = Content_Range;
	Range = Range;

	Age = Age;
	Cache_Control = Cache_Control;
	Expires = Expires;
	Pragma = Pragma;
	Warning = Warning;

	WWW_Authenticate = WWW_Authenticate;
	Authorization = Authorization;
	Proxy_Authenticate = Proxy_Authenticate;
	Proxy_Authorization = Proxy_Authorization;

	Forwarded = Forwarded;

	Hobareg = Hobareg;

	Authentication_Info = Authentication_Info;
	Proxy_Authentication_Info = Proxy_Authentication_Info;

	ALPN = ALPN;

	CalDAV_Timezones = CalDAV_Timezones;

	Alt_Svc = Alt_Svc;
	Alt_Used = Alt_Used;
}
