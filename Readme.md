# Verify id_token signature

Here is how to compile and run.

```text
cargo clippy; cargo fmt
cargo build --release
./target/release/jwt_verify --token $token --client-id 407408718192.apps.googleusercontent.com
```

Example output

```text
$ ./target/release/jwt_verify --token $token --client-id 407408718192.apps.googleusercontent.com
Full token header: Header { typ: Some("JWT"), alg: RS256, cty: None, jku: None, jwk: None, kid: Some("f2e11986282de93f27b264fd2a4de192993dcb8c"), x5u: None, x5c: None, x5t: None, x5t_s256: None }
Algorithm from JWT header: RS256
Issuer from token: https://accounts.google.com
JWK found: Jwk { kty: "RSA", kid: "f2e11986282de93f27b264fd2a4de192993dcb8c", alg: "RS256", n: Some("zaUomGGU1qSBxBHOQRk5fF7rOVVzG5syHhJYociRyyvvMOM6Yx_n7QFrwKxW1Gv-YKPDsvs-ksSN5YsozOTb9Y2HlPsOXrnZHQTQIdjWcfUz-TLDknAdJsK3A0xZvq5ud7ElIrXPFS9UvUrXDbIv5ruv0w4pvkDrp_Xdhw32wakR5z0zmjilOHeEJ73JFoChOaVxoRfpXkFGON5ZTfiCoO9o0piPROLBKUtIg_uzMGzB6znWU8Yfv3UlGjS-ixApSltsXZHLZfat1sUvKmgT03eXV8EmNuMccrhLl5AvqKT6E5UsTheSB0veepQgX8XCEex-P3LCklisnen3UKOtLw"), e: Some("AQAB"), x: None, y: None, crv: None, k: None }
Constructed PEM: -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAzaUomGGU1qSBxBHOQRk5fF7rOVVzG5syHhJYociRyyvvMOM6Yx/n
7QFrwKxW1Gv+YKPDsvs+ksSN5YsozOTb9Y2HlPsOXrnZHQTQIdjWcfUz+TLDknAd
JsK3A0xZvq5ud7ElIrXPFS9UvUrXDbIv5ruv0w4pvkDrp/Xdhw32wakR5z0zmjil
OHeEJ73JFoChOaVxoRfpXkFGON5ZTfiCoO9o0piPROLBKUtIg/uzMGzB6znWU8Yf
v3UlGjS+ixApSltsXZHLZfat1sUvKmgT03eXV8EmNuMccrhLl5AvqKT6E5UsTheS
B0veepQgX8XCEex+P3LCklisnen3UKOtLwIDAQAB
-----END RSA PUBLIC KEY-----

Decoding key created
Signature is valid. Claims: Claims { iss: "https://accounts.google.com", sub: "123456789", email: "xxxxxx@gmail.com", exp: 1721997430, aud: "407408718192.apps.googleusercontent.com", iat: 1721993830 }
Issuer is valid
Audience is valid
Token is valid at the current time
Token is valid. Claims: Claims { iss: "https://accounts.google.com", sub: "123456789", email: "xxxxxx@gmail.com", exp: 1721997430, aud: "407408718192.apps.googleusercontent.com", iat: 1721993830 }
```
