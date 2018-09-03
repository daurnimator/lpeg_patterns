local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"

local C = lpeg.C
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P

-- RFC 7235 Section 2
local auth_scheme = http_core.token
local auth_param = Cg(http_core.token / string.lower * http_core.BWS * P"=" * http_core.BWS * (http_core.token + http_core.quoted_string))
local token68 = C((core.ALPHA + core.DIGIT + P"-" + P"." + P"_" + P"~" + P"+" + P"/" )^1 * (P"=")^0)
-- TODO: each parameter name MUST only occur once per challenge
local challenge = auth_scheme * (core.SP^1 * (Cf(Ct(true) * http_core.comma_sep(auth_param), rawset) + token68))^-1
local credentials = challenge

-- RFC 7235 Section 4
local WWW_Authenticate = http_core.comma_sep_trim(Ct(challenge), 1)
local Authorization = credentials
local Proxy_Authenticate = WWW_Authenticate
local Proxy_Authorization = Authorization

-- RFC 7615
local Authentication_Info = http_core.comma_sep_trim(auth_param)
local Proxy_Authentication_Info = http_core.comma_sep_trim(auth_param)

return {
	Authentication_Info = Authentication_Info;
	Authorization = Authorization;
	Proxy_Authenticate = Proxy_Authenticate;
	Proxy_Authentication_Info = Proxy_Authentication_Info;
	Proxy_Authorization = Proxy_Authorization;
	WWW_Authenticate = WWW_Authenticate;
}
