package = "lpeg_patterns"
version = "scm-0"

description= {
	summary = "a collection of LPEG patterns";
	license = "MIT/X11";
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
		["lpeg_patterns.phone"] = "lpeg_patterns/phone.lua";
		["lpeg_patterns.language"] = "lpeg_patterns/language.lua";
	};
}
