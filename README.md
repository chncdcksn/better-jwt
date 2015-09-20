# better-jwt

Simple JWT-like sign/verify library

This library DOES NOT conform to the JWT spec, and is not compatible with other
JWT libraries. The primary differences between this and the official JWT spec
are in the header. Instead of the official header format, the header currently includes the following key/value pairs.

* issued: Unix timestamp when the JWT was issued.
* expires (optional): Seconds from issued until JWT is expired.

In future updates, other header properties such as `issuer`, `audience`, etc.
may be added to the header.

better-jwt is still very early software, and should not yet be used in
production.

## API

`.sign(Object payload, String secret, String algorithm[, Object options]) -> String`

Signs the payload and returns a JWT as a string.

Parameters:

* payload: Object that will be signed.
* secret: String containing HMAC secret.
* algorithm: String containing one of the algorithms listed in the next section.
* options (optional): Object containing the key/value pairs listed below.

Available options:

* expires: Time in seconds until the JWT is expired.

`.verify(String jwt, String secret, String algorithm[, Object options]) -> Object`

Verifies a JWT's signature and if valid, returns the payload.

Parameters:

* jwt: String containing a value returned by `.sign()`.
* secret: String containing HMAC secret.
* algorithm: String containing one of the algorithms listed in the next section.
* options (optional): Object containing the key/value pairs listed below.

`.decode(String jwt) -> Object`

Decodes the payload of the JWT --WITHOUT-- verifying the signature.

Parameters:

* jwt: String containing a value returned by `.sign()`.

## Algorithms

* hmac256
* hmac384
* hmac512

## Todo

* Security testing
* Unit tests
