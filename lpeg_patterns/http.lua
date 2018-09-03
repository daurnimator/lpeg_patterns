-- HTTP related patterns

local _M = {}

-- RFC 7230
local http_core = require "lpeg_patterns.http.core"
_M.OWS = http_core.OWS
_M.RWS = http_core.RWS
_M.BWS = http_core.BWS

_M.chunk_ext = http_core.chunk_ext
_M.comment = http_core.comment
_M.field_name = http_core.field_name
_M.field_value = http_core.field_value
_M.header_field = http_core.header_field
_M.qdtext = http_core.qdtext
_M.quoted_string = http_core.quoted_string
_M.request_line = http_core.request_line
_M.request_target = http_core.request_target
_M.token = http_core.token

_M.Connection = http_core.Connection
_M.Content_Length = http_core.Content_Length
_M.Host = http_core.Host
_M.TE = http_core.TE
_M.Trailer = http_core.Trailer
_M.Transfer_Encoding = http_core.Transfer_Encoding
_M.Upgrade = http_core.Upgrade
_M.Via = http_core.Via

-- RFC 7231
local http_semantics = require "lpeg_patterns.http.semantics"

_M.IMF_fixdate = http_semantics.IMF_fixdate

_M.Accept = http_semantics.Accept
_M.Accept_Charset = http_semantics.Accept_Charset
_M.Accept_Encoding = http_semantics.Accept_Encoding
_M.Accept_Language = http_semantics.Accept_Language
_M.Allow = http_semantics.Allow
_M.Content_Encoding = http_semantics.Content_Encoding
_M.Content_Language = http_semantics.Content_Language
_M.Content_Location = http_semantics.Content_Location
_M.Content_Type = http_semantics.Content_Type
_M.Date = http_semantics.Date
_M.Expect = http_semantics.Expect
_M.From = http_semantics.From
_M.Location = http_semantics.Location
_M.Max_Forwards = http_semantics.Max_Forwards
_M.Referer = http_semantics.Referer
_M.Retry_After = http_semantics.Retry_After
_M.Server = http_semantics.Server
_M.User_Agent = http_semantics.User_Agent
_M.Vary = http_semantics.Vary

-- RFC 7232
local http_conditional = require "lpeg_patterns.http.conditional"
_M.ETag = http_conditional.ETag
_M.If_Match = http_conditional.If_Match
_M.If_Modified_Since = http_conditional.If_Modified_Since
_M.If_None_Match = http_conditional.If_None_Match
_M.If_Unmodified_Since = http_conditional.If_Unmodified_Since
_M.Last_Modified = http_conditional.Last_Modified

-- RFC 7233
local http_range = require "lpeg_patterns.http.range"
_M.Accept_Ranges = http_range.Accept_Ranges
_M.Range = http_range.Range
_M.If_Range = http_range.If_Range
_M.Content_Range = http_range.Content_Range

-- RFC 7234
local http_caching = require "lpeg_patterns.http.caching"
_M.Age = http_caching.Age
_M.Cache_Control = http_caching.Cache_Control
_M.Expires = http_caching.Expires
_M.Pragma = http_caching.Pragma
_M.Warning = http_caching.Warning

-- RFC 7235
local http_authentication = require "lpeg_patterns.http.authentication"
_M.WWW_Authenticate = http_authentication.WWW_Authenticate
_M.Authorization = http_authentication.Authorization
_M.Proxy_Authenticate = http_authentication.Proxy_Authenticate
_M.Proxy_Authorization = http_authentication.Proxy_Authorization

-- WebDav
local http_webdav = require "lpeg_patterns.http.webdav"
_M.CalDAV_Timezones = http_webdav.CalDAV_Timezones
_M.DASL = http_webdav.DASL
_M.DAV = http_webdav.DAV
_M.Depth = http_webdav.Depth
_M.Destination = http_webdav.Destination
_M.If = http_webdav.If
_M.If_Schedule_Tag_Match = http_webdav.If_Schedule_Tag_Match
_M.Lock_Token = http_webdav.Lock_Token
_M.Overwrite = http_webdav.Overwrite
_M.Schedule_Reply = http_webdav.Schedule_Reply
_M.Schedule_Tag = http_webdav.Schedule_Tag
_M.TimeOut = http_webdav.TimeOut

-- RFC 5023
_M.SLUG = require "lpeg_patterns.http.slug".SLUG

-- RFC 5789
_M.Accept_Patch = http_core.comma_sep_trim(http_semantics.media_type, 1)

-- RFC 5988
_M.Link = require "lpeg_patterns.http.link".Link

-- RFC 6265
local http_cookie = require "lpeg_patterns.http.cookie"
_M.Cookie = http_cookie.Cookie
_M.Set_Cookie = http_cookie.Set_Cookie

-- RFC 6266
_M.Content_Disposition = require "lpeg_patterns.http.disposition".Content_Disposition

-- RFC 6454
_M.Origin = require "lpeg_patterns.http.origin".Origin

-- RFC 6455
local http_websocket = require "lpeg_patterns.http.websocket"
_M.Sec_WebSocket_Accept = http_websocket.Sec_WebSocket_Accept
_M.Sec_WebSocket_Key = http_websocket.Sec_WebSocket_Key
_M.Sec_WebSocket_Extensions = http_websocket.Sec_WebSocket_Extensions
_M.Sec_WebSocket_Protocol_Client = http_websocket.Sec_WebSocket_Protocol_Client
_M.Sec_WebSocket_Protocol_Server = http_websocket.Sec_WebSocket_Protocol_Server
_M.Sec_WebSocket_Version_Client = http_websocket.Sec_WebSocket_Version_Client
_M.Sec_WebSocket_Version_Server = http_websocket.Sec_WebSocket_Version_Server

-- RFC 6797
_M.Strict_Transport_Security = require "lpeg_patterns.http.sts".Strict_Transport_Security

-- RFC 7034
_M.X_Frame_Options = require "lpeg_patterns.http.frameoptions".X_Frame_Options

-- RFC 7089
_M.Accept_Datetime = http_semantics.IMF_fixdate
_M.Memento_Datetime = http_semantics.IMF_fixdate

-- RFC 7239
_M.Forwarded = require "lpeg_patterns.http.forwarded".Forwarded

-- RFC 7469
local http_pkp = require "lpeg_patterns.http.pkp"
_M.Public_Key_Pins = http_pkp.Public_Key_Pins
_M.Public_Key_Pins_Report_Only = http_pkp.Public_Key_Pins_Report_Only

-- RFC 7486
_M.Hobareg = require "lpeg_patterns.http.hoba".Hobareg

-- RFC 7615
_M.Authentication_Info = http_authentication.Authentication_Info
_M.Proxy_Authentication_Info = http_authentication.Proxy_Authentication_Info

-- RFC 7639
_M.ALPN = require "lpeg_patterns.http.alpn".ALPN

-- RFC 7838
local http_alternate = require "lpeg_patterns.http.alternate"
_M.Alt_Svc = http_alternate.Alt_Svc
_M.Alt_Used = http_alternate.Alt_Used

-- https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-06#section-2.1
_M.Expect_CT = require "lpeg_patterns.http.expect_ct".Expect_CT

-- https://www.w3.org/TR/referrer-policy/#referrer-policy-header
_M.Referrer_Policy = require "lpeg_patterns.http.referrer_policy".Referrer_Policy

return _M
