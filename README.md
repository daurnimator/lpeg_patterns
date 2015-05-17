A collection of [LPEG](http://www.inf.puc-rio.br/~roberto/lpeg/lpeg.html) patterns

## Use cases

  - Strict validatation of user input
  - Searching free-form input


## Modules

### `core`

A small module implementing commonly used rules from [RFC-5234 appendix B.1](https://tools.ietf.org/html/rfc5234#appendix-B.1)

  - `ALPHA` (pattern)
  - `BIT` (pattern)
  - `CHAR` (pattern)
  - `CRLF` (pattern)
  - `CTL` (pattern)
  - `DIGIT` (pattern)
  - `HEXDIG` (pattern)
  - `VCHAR` (pattern)
  - `WSP` (pattern)


### `IPv4`

  - `IPv4address` (pattern): parses an IPv4 address in dotted decimal notation. on success, returns addresses as an IPv4 object
  - `IPv4_methods` (table):
      - `unpack` (function): the IPv4 address as a series of 4 8 bit numbers
      - `binary` (function): the IPv4 address as a 4 byte binary string
  - `IPv4_mt` (table): metatable given to IPv4 objects
      - `__index` (table): `IPv4_methods`
      - `__tostring` (function): returns the IPv4 address in dotted decimal notation


### `IPv6`

  - `IPv6address` (pattern): parses an IPv6 address
  - `IPv6addrz` (pattern): parses an IPv6 address with optional "ZoneID" (see [RFC-6874](https://tools.ietf.org/html/rfc6874))
  - `IPv6_methods` (table): methods available on IPv6 objects
      - `unpack` (function): the IPv6 address as a series of 8 16bit numbers
      - `binary` (function): the IPv6 address as a 16 byte binary string
  - `IPv6_mt` (table): metatable given to IPv6 objects
      - `__tostring` (function): will return the IPv6 address as a valid IPv6 string


### `uri`

Parses URIs as described in [RFC-3986](https://tools.ietf.org/html/rfc3986).

  - `uri` (pattern): on success, returns a table with fields: (similar to [luasocket](http://w3.impa.br/~diego/software/luasocket/url.html))
      - `scheme`
      - `userinfo`
      - `host`
      - `port`
      - `path`
      - `query`
      - `fragment`
  - `sane_uri` (pattern): a variant that shouldn't match things that people would not normally consider URIs.
    e.g. uris without a hostname


### `email`

  - `email` (pattern): follows [RFC-5322 section 3.4.1](http://tools.ietf.org/html/rfc5322#section-3.4.1)
  - `email_nocfws` (pattern): a variant that doesn't allow for comments or folding whitespace


### `phone`

  - `phone` (pattern): includes detailed checking for:
      - USA phone numbers using the [NANP](https://en.wikipedia.org/wiki/North_American_Numbering_Plan)
