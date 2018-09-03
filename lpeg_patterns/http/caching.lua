-- RFC 7234
-- Hypertext Transfer Protocol (HTTP/1.1): Caching

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local http_semantics = require "lpeg_patterns.http.semantics"
local uri = require "lpeg_patterns.uri"

local Cc = lpeg.Cc
local Cg = lpeg.Cg
local P = lpeg.P

-- RFC 7234 Section 1.2.1
local delta_seconds = core.DIGIT^1 / tonumber

-- RFC 7234 Section 5.1
local Age = delta_seconds

-- RFC 7234 Section 5.2
local cache_directive = http_core.token / string.lower * ((P"=" * (http_core.token + http_core.quoted_string)) + Cc(true))
local Cache_Control = http_core.comma_sep_trim(Cg(cache_directive), 1)

-- RFC 7234 Section 5.3
local Expires = http_semantics.HTTP_date

-- RFC 7234 Section 5.4
local extension_pragma = http_core.token * (P"=" * (http_core.token + http_core.quoted_string))^-1
local pragma_directive = "no_cache" + extension_pragma
local Pragma = http_core.comma_sep_trim(pragma_directive, 1)

-- RFC 7234 Section 5.5
local warn_code = core.DIGIT * core.DIGIT * core.DIGIT
local warn_agent = (uri.host * (P":" * uri.port)^-1) + http_core.pseudonym
local warn_text = http_core.quoted_string
local warn_date = core.DQUOTE * http_semantics.HTTP_date * core.DQUOTE
local warning_value = warn_code * core.SP * warn_agent * core.SP * warn_text * (core.SP * warn_date)^-1
local Warning = http_core.comma_sep_trim(warning_value, 1)

return {
	Age = Age;
	Cache_Control = Cache_Control;
	Expires = Expires;
	Pragma = Pragma;
	Warning = Warning;
}
