A collection of [LPEG](http://www.inf.puc-rio.br/~roberto/lpeg/lpeg.html) patterns

## Use cases

  - Strict validation of user input
  - Searching free-form input


## Modules

### `core`

A small module implementing commonly used rules from [RFC-5234 appendix B.1](https://tools.ietf.org/html/rfc5234#appendix-B.1)

  - `ALPHA` (pattern)
  - `BIT` (pattern)
  - `CHAR` (pattern)
  - `CR` (pattern)
  - `CRLF` (pattern)
  - `CTL` (pattern)
  - `DIGIT` (pattern)
  - `DQUOTE` (pattern)
  - `HEXDIG` (pattern)
  - `HTAB` (pattern)
  - `LF` (pattern)
  - `LWSP` (pattern)
  - `OCTET` (pattern)
  - `SP` (pattern)
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

IPv4 "dotted decimal notation" in this document refers to "strict" form (see [RFC-6943 section 3.1.1](https://tools.ietf.org/html/rfc6943#section-3.1.1)) unless otherwise noted.


### `IPv6`

  - `IPv6address` (pattern): parses an IPv6 address
  - `IPv6addrz` (pattern): parses an IPv6 address with optional "ZoneID" (see [RFC-6874](https://tools.ietf.org/html/rfc6874))
  - `IPv6_methods` (table): methods available on IPv6 objects
      - `unpack` (function): the IPv6 address as a series of 8 16bit numbers, optionally followed by zoneid
      - `binary` (function): the IPv6 address as a 16 byte binary string
      - `setzoneid` (function): set the zoneid of this IPv6 address
  - `IPv6_mt` (table): metatable given to IPv6 objects
      - `__tostring` (function): will return the IPv6 address as a valid IPv6 string


### `uri`

Parses URIs as described in [RFC-3986](https://tools.ietf.org/html/rfc3986).

  - `uri` (pattern): on success, returns a table with fields: (similar to [luasocket](http://w3.impa.br/~diego/software/luasocket/url.html#parse))
      - `scheme`
      - `userinfo`
      - `host`
      - `port`
      - `path`
      - `query`
      - `fragment`
  - `absolute_uri` (pattern): similar to `uri`, but does not permit fragments
  - `uri_reference` (pattern): similar to `uri`, but permits relative URIs
  - `relative_part` (pattern): matches a relative uri not including query and fragment; data is held in named group captures `"userinfo"`, `"host"`, `"port"`, `"path"`
  - `scheme` (pattern): matches the scheme portion of a URI
  - `userinfo` (pattern): matches the userinfo portion of a URI
  - `host` (pattern): matches the host portion of a URI
  - `port` (pattern): matches the port portion of a URI
  - `authority` (pattern): matches the authority portion of a URI; data is held in named group captures of `"userinfo"`, `"host"`, `"port"`
  - `path` (pattern): matches the path portion of a URI. Captures `nil` for the empty path.
  - `segment` (pattern): matches a path segment (a piece of a path without a `/`)
  - `query` (pattern): matches the query portion of a URI
  - `fragment` (pattern): matches the fragment portion of a URI
  - `sane_uri` (pattern): a variant that shouldn't match things that people would not normally consider URIs.
    e.g. uris without a hostname
  - `sane_host` (pattern): a variant that shouldn't match things that people would not normally consider valid hosts.
  - `sane_authority` (pattern): a variant that shouldn't match things that people would not normally consider valid hosts.
  - `pct_encoded` (pattern): matches a percent encoded octet, produces a capture of the normalised form.


### `email`

  - `mailbox` (pattern): the mailbox format: matches either `name_addr` or an addr-spec.
  - `name_addr` (pattern): the name and address format i.e. `Display Name<email@example.com>`
    Has captures of the local_part and the domain. Captures the display name in the named capture `"display"`
  - `email` (pattern): also known as an "addr-spec"; follows [RFC-5322 section 3.4.1](http://tools.ietf.org/html/rfc5322#section-3.4.1)
    Has captures of the local_part and the domain
    Be careful trying to reconstruct the email address from the captures; you may need escaping
  - `local_part` (pattern): the bit before the `@` in an email address
  - `domain` (pattern): the bit after the `@` in an email address
  - `email_nocfws` (pattern): a variant that doesn't allow for comments or folding whitespace
  - `local_part_nocfws` (pattern): the bit before the `@` in an email address; no comments or folding whitespace allowed.
  - `domain_nocfws` (pattern):  the bit after the `@` in an email address; no comments or folding whitespace allowed.



### `phone`

  - `phone` (pattern): includes detailed checking for:
      - USA phone numbers using the [NANP](https://en.wikipedia.org/wiki/North_American_Numbering_Plan)


### `language`

Patterns for definitions from [RFC-4646 Section 2.1](https://tools.ietf.org/html/rfc4646#section-2.1)

  - `langtag` (pattern): Capture is a table with the language tag decomposed into components:
      - `language`
      - `extlang` (optional)
      - `script` (optional)
      - `region` (optional)
      - `variant` (optional): an array
      - `extension` (optional): a dictionary from singleton to value
      - `privateuse` (optional): an array
  - `privateuse` (pattern): captures an array
  - `Language_Tag` (pattern): captures the whole language tag
