use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use jsonwebtoken::crypto::verify;
use jsonwebtoken::{Algorithm, DecodingKey};
use pkcs1::LineEnding;
use reqwest::blocking::get;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
struct Opts {
    #[clap(short, long)]
    token: String,
    #[clap(short, long)]
    client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    email: String,
    exp: usize,
    aud: String,
    iat: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenIdConfiguration {
    jwks_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    alg: String,
    n: Option<String>,   // RSA modulus
    e: Option<String>,   // RSA exponent
    x: Option<String>,   // EC x-coordinate
    y: Option<String>,   // EC y-coordinate
    crv: Option<String>, // EC curve
    k: Option<String>,   // Symmetric key
}

// Fetch OpenID configuration for a given issuer
fn fetch_openid_configuration(issuer: &str) -> Result<OpenIdConfiguration, Box<dyn Error>> {
    let url = format!("{}/.well-known/openid-configuration", issuer);
    let resp = get(url)?;
    let config: OpenIdConfiguration = resp.json()?;
    Ok(config)
}

// Fetch JWKS (JSON Web Key Set) from a URL
fn fetch_jwks(jwks_url: &str) -> Result<Jwks, Box<dyn Error>> {
    let resp = get(jwks_url)?;
    let jwks: Jwks = resp.json()?;
    Ok(jwks)
}

// Find the JWK with the matching 'kid'
fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|key| key.kid == kid)
}

// Decode base64 URL-safe strings
fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| e.into())
}

// Convert JWK to DecodingKey based on its algorithm
fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, Box<dyn Error>> {
    match jwk.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = decode_base64_url_safe(jwk.n.as_ref().ok_or("Missing 'n' for RSA key")?)?;
            let e = decode_base64_url_safe(jwk.e.as_ref().ok_or("Missing 'e' for RSA key")?)?;
            let rsa_public_key =
                RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))?;
            let pem = rsa_public_key.to_pkcs1_pem(LineEnding::default())?;
            println!("Constructed PEM: {}", pem);
            Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?)
        }
        "ES256" | "ES384" | "ES512" => {
            let x = decode_base64_url_safe(jwk.x.as_ref().ok_or("Missing 'x' for EC key")?)?;
            let x_str = std::str::from_utf8(&x)?;
            let y = decode_base64_url_safe(jwk.y.as_ref().ok_or("Missing 'y' for EC key")?)?;
            let y_str = std::str::from_utf8(&y)?;
            Ok(DecodingKey::from_ec_components(x_str, y_str)?)
        }
        "HS256" | "HS384" | "HS512" => {
            let k = decode_base64_url_safe(jwk.k.as_ref().ok_or("Missing 'k' for symmetric key")?)?;
            Ok(DecodingKey::from_secret(&k))
        }
        _ => Err(format!("Unsupported algorithm: {}", jwk.alg).into()),
    }
}

// Extract the issuer from the token payload
fn extract_iss_from_token(token: &str) -> Result<String, Box<dyn Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".into());
    }
    let payload = parts[1];
    let decoded_payload = decode_base64_url_safe(payload)?;
    let claims: Claims = serde_json::from_slice(&decoded_payload)?;
    Ok(claims.iss)
}

// Verify the token signature
fn verify_signature(
    token: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<bool, Box<dyn Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".into());
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = decode_base64_url_safe(parts[2])?;
    let signature_str = general_purpose::URL_SAFE_NO_PAD.encode(signature);

    match verify(&signature_str, message.as_bytes(), decoding_key, alg) {
        Ok(valid) => Ok(valid),
        Err(err) => {
            println!("Failed to verify signature: {:?}", err);
            Err(Box::new(err))
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let header = jsonwebtoken::decode_header(&opts.token)?;
    println!("Full token header: {:?}", header);

    let kid = header.kid.ok_or("Token does not have a 'kid' field")?;
    let alg = header.alg;

    println!("Algorithm from JWT header: {:?}", alg);

    let issuer = extract_iss_from_token(&opts.token)?;
    println!("Issuer from token: {}", issuer);
    let config = fetch_openid_configuration(&issuer)?;
    let jwks = fetch_jwks(&config.jwks_uri)?;

    let jwk = find_jwk(&jwks, &kid).ok_or("No matching key found in JWKS")?;
    println!("JWK found: {:?}", jwk);

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;
    println!("Decoding key created");

    let signature_valid = verify_signature(&opts.token, &decoding_key, alg)?;
    if !signature_valid {
        return Err("Signature is not valid".into());
    }

    let decoded_payload = decode_base64_url_safe(opts.token.split('.').collect::<Vec<&str>>()[1])?;
    let claims: Claims = serde_json::from_slice(&decoded_payload)?;
    println!("Signature is valid. Claims: {:?}", claims);

    if claims.iss != issuer {
        return Err("Invalid issuer".into());
    }
    println!("Issuer is valid");

    if claims.aud != opts.client_id {
        return Err(format!(
            "Invalid audience: expected {}, got {}",
            opts.client_id, claims.aud
        )
        .into());
    }
    println!("Audience is valid");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;

    if now < claims.iat || now > claims.exp {
        return Err("Token is not valid at the current time".into());
    }
    println!("Token is valid at the current time");

    println!("Token is valid. Claims: {:?}", claims);
    Ok(())
}
