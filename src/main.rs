use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation, TokenData};
use reqwest::blocking::get;
use rsa::pkcs1::EncodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use rsa::{RsaPublicKey, BigUint};
use pkcs1::LineEnding;

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
    n: Option<String>, // RSA modulus
    e: Option<String>, // RSA exponent
    x: Option<String>, // EC x-coordinate
    y: Option<String>, // EC y-coordinate
    crv: Option<String>, // EC curve
    k: Option<String>, // Symmetric key
}

fn fetch_openid_configuration(issuer: &str) -> Result<OpenIdConfiguration, Box<dyn Error>> {
    let url = format!("{}/.well-known/openid-configuration", issuer);
    let resp = get(&url)?;
    let config: OpenIdConfiguration = resp.json()?;
    Ok(config)
}

fn fetch_jwks(jwks_url: &str) -> Result<Jwks, Box<dyn Error>> {
    let resp = get(jwks_url)?;
    let jwks: Jwks = resp.json()?;
    Ok(jwks)
}

fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|key| key.kid == kid)
}

fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    general_purpose::URL_SAFE_NO_PAD.decode(input).map_err(|e| e.into())
}

fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, Box<dyn Error>> {
    match jwk.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = decode_base64_url_safe(jwk.n.as_ref().ok_or("Missing 'n' for RSA key")?)?;
            let e = decode_base64_url_safe(jwk.e.as_ref().ok_or("Missing 'e' for RSA key")?)?;
            // println!("Decoded n: {:?}", n);
            // println!("Decoded e: {:?}", e);
            let rsa_public_key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))?;
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
        _ => Err(format!("Unsupported algorithm: {}", jwk.alg).into())
    }
}

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

fn verify_signature(token: &str, decoding_key: &DecodingKey, alg: Algorithm) -> Result<TokenData<Claims>, Box<dyn Error>> {
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;  // We will manually validate expiration
    validation.validate_aud = false;  // We will manually validate audience
    
    match jsonwebtoken::decode::<Claims>(token, decoding_key, &validation) {
        Ok(data) => Ok(data),
        Err(err) => {
            println!("Failed to verify signature: {:?}", err);
            Err(Box::new(err))
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let header = decode_header(&opts.token)?;
    println!("Full token header: {:?}", header);

    let kid = header.kid.ok_or("Token does not have a 'kid' field")?;
    let alg = header.alg;

    println!("Algorithm from JWT header: {:?}", alg);

    let issuer = extract_iss_from_token(&opts.token)?;
    println!("Issuer from token: {}", issuer);
    let config = fetch_openid_configuration(&issuer)?;
    let jwks = fetch_jwks(&config.jwks_uri)?;

    let jwk = find_jwk(&jwks, &kid).ok_or("No matching key found in JWKS")?;

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;
    // println!("Decoding key created");

    let token_data = verify_signature(&opts.token, &decoding_key, alg)?;
    let claims = token_data.claims;
    println!("Signature is valid.");

    if claims.iss == issuer {
        println!("Issuer is valid");
    } else {
        return Err("Invalid issuer".into());
    }

    if claims.aud == opts.client_id {
        println!("Audience is valid");
    } else {
        return Err(format!("Invalid audience: expected {}, got {}", opts.client_id, claims.aud).into());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;

    if now >= claims.iat && now <= claims.exp {
        println!("Token is valid at the current time");
    } else {
        return Err("Token is not valid at the current time".into());
    }

    println!("Token is valid. Claims: {:?}", claims);
    Ok(())
}
