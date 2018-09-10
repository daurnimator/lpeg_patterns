package = "lpeg_patterns"
version = "scm-0"

description= {
	summary = "a collection of LPEG patterns";
	license = "MIT";
}

dependencies = {
	"lua";
	"lpeg";
}

source = {
	url = "git://github.com/daurnimator/lpeg_patterns.git";
}

build = {
	type = "builtin";
	modules = {
		["lpeg_patterns.util"] = "lpeg_patterns/util.lua";
		["lpeg_patterns.core"] = "lpeg_patterns/core.lua";
		["lpeg_patterns.IPv4"] = "lpeg_patterns/IPv4.lua";
		["lpeg_patterns.IPv6"] = "lpeg_patterns/IPv6.lua";
		["lpeg_patterns.uri"] = "lpeg_patterns/uri.lua";
		["lpeg_patterns.email"] = "lpeg_patterns/email.lua";
		["lpeg_patterns.http"] = "lpeg_patterns/http.lua";
		["lpeg_patterns.http.alpn"] = "lpeg_patterns/http/alpn.lua";
		["lpeg_patterns.http.alternate"] = "lpeg_patterns/http/alternate.lua";
		["lpeg_patterns.http.authentication"] = "lpeg_patterns/http/authentication.lua";
		["lpeg_patterns.http.caching"] = "lpeg_patterns/http/caching.lua";
		["lpeg_patterns.http.conditional"] = "lpeg_patterns/http/conditional.lua";
		["lpeg_patterns.http.cookie"] = "lpeg_patterns/http/cookie.lua";
		["lpeg_patterns.http.core"] = "lpeg_patterns/http/core.lua";
		["lpeg_patterns.http.disposition"] = "lpeg_patterns/http/disposition.lua";
		["lpeg_patterns.http.expect_ct"] = "lpeg_patterns/http/expect_ct.lua";
		["lpeg_patterns.http.forwarded"] = "lpeg_patterns/http/forwarded.lua";
		["lpeg_patterns.http.frameoptions"] = "lpeg_patterns/http/frameoptions.lua";
		["lpeg_patterns.http.hoba"] = "lpeg_patterns/http/hoba.lua";
		["lpeg_patterns.http.link"] = "lpeg_patterns/http/link.lua";
		["lpeg_patterns.http.origin"] = "lpeg_patterns/http/origin.lua";
		["lpeg_patterns.http.parameters"] = "lpeg_patterns/http/parameters.lua";
		["lpeg_patterns.http.pkp"] = "lpeg_patterns/http/pkp.lua";
		["lpeg_patterns.http.range"] = "lpeg_patterns/http/range.lua";
		["lpeg_patterns.http.referrer_policy"] = "lpeg_patterns/http/referrer_policy.lua";
		["lpeg_patterns.http.semantics"] = "lpeg_patterns/http/semantics.lua";
		["lpeg_patterns.http.slug"] = "lpeg_patterns/http/slug.lua";
		["lpeg_patterns.http.sts"] = "lpeg_patterns/http/sts.lua";
		["lpeg_patterns.http.util"] = "lpeg_patterns/http/util.lua";
		["lpeg_patterns.http.webdav"] = "lpeg_patterns/http/webdav.lua";
		["lpeg_patterns.http.websocket"] = "lpeg_patterns/http/websocket.lua";
		["lpeg_patterns.phone"] = "lpeg_patterns/phone.lua";
		["lpeg_patterns.language"] = "lpeg_patterns/language.lua";
		["lpeg_patterns.utf8"] = "lpeg_patterns/utf8.lua";
	};
}
