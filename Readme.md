# Verify id_token signature

## How to

Here is how to compile and run.

```text
cargo clippy; cargo fmt
cargo build --release
./target/release/jwt_verify --token $token --client-id 407408718192.apps.googleusercontent.com
```

Example output

```text
$ ./target/release/jwt_verify -h
Usage: jwt_verify [OPTIONS] --token <TOKEN>

Options:
  -t, --token <TOKEN>          
  -c, --client-id <CLIENT_ID>  
  -i, --issuer <ISSUER>        
  -h, --help                   Print help

$ ./target/release/jwt_verify -t $token
Expiration check failed: Token already expired: expires at 1721972706 < now 1722041928

Summary:
 Signature check: pass
 Audience(ClientId) check: skip
 Issuer check: skip
 Not Before check: pass
 Expiration check: fail

Claims in id_token: 
 Claims { iss: "https://accounts.google.com", sub: "123456789", email: "xxxxxxx@gmail.com", exp: 1721972706, aud: "xxxxx.apps.googleusercontent.com", iat: 1721969106, nbf: Some(1721968806) }


$ ./target/release/jwt_verify -t $token -i https://accounts.google.com -c 407408718192.apps.googleusercontent.com

Summary:
 Signature check: pass
 Audience check: pass
 Issuer check: pass
 Not Before check: skip
 Expiration check: pass

Claims in id_token: 
 Claims { iss: "https://accounts.google.com", sub: "123456789", email: "xxxxxx@gmail.com", exp: 1722045669, aud: "407408718192.apps.googleusercontent.com", iat: 1722042069, nbf: None }

```

## Get id_token example

Obtain id_token from Google's OAuth 2.0 Playground

- <https://developers.google.com/oauthplayground>
- Put scopes for example, "openid,email,profile" in the box just above the "Authorize APIs" button and then click that button.
- Alternatively, you can select the scopes in the selection box and then click the "Authorize APIs" button.
- Select an account and proceed in the Google's OAuth2 pages.
- Click the "Exchange authorization code for tokens" button.
- You see the response from the Google's token endpoint. Inside it you can find the id_token.
