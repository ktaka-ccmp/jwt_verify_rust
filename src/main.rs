use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use jsonwebtoken::crypto::verify;
use jsonwebtoken::{Algorithm, DecodingKey};
use log::{debug, error, info};
use pkcs1::EncodeRsaPublicKey;
use pkcs1::LineEnding;
use reqwest::blocking::get;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Parser)]
struct Opts {
    #[clap(short, long)]
    token: String,
    #[clap(short, long)]
    client_id: Option<String>,
    #[clap(short, long)]
    issuer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    email: String,
    exp: usize,
    aud: String,
    iat: usize,
    nbf: Option<usize>,
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
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    crv: Option<String>,
    k: Option<String>,
}

#[derive(Error, Debug)]
enum TokenVerificationError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decoding failed: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("No matching key found in JWKS")]
    NoMatchingKey,
    #[error("Missing key component: {0}")]
    MissingKeyComponent(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("PKCS1 error: {0}")]
    Pkcs1Error(#[from] pkcs1::Error),
}

fn fetch_openid_configuration(issuer: &str) -> Result<OpenIdConfiguration, TokenVerificationError> {
    let url = format!("{}/.well-known/openid-configuration", issuer);
    info!("Fetching OpenID configuration from: {}", url);
    let resp = get(url)?;
    let config: OpenIdConfiguration = resp.json()?;
    debug!("Fetched OpenID configuration: {:?}", config);
    Ok(config)
}

fn fetch_jwks(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    info!("Fetching JWKS from: {}", jwks_url);
    let resp = get(jwks_url)?;
    let jwks: Jwks = resp.json()?;
    debug!("Fetched JWKS: {:?}", jwks);
    Ok(jwks)
}

fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|key| key.kid == kid)
}

fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, TokenVerificationError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(TokenVerificationError::from)
}

fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, TokenVerificationError> {
    match jwk.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = decode_base64_url_safe(
                jwk.n
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("n".to_string()))?,
            )?;
            let e = decode_base64_url_safe(
                jwk.e
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("e".to_string()))?,
            )?;
            let rsa_public_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            )?;
            let pem = rsa_public_key.to_pkcs1_pem(LineEnding::default())?;
            debug!("Constructed PEM: {}", pem);
            Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?)
        }
        "ES256" | "ES384" | "ES512" => {
            let x = decode_base64_url_safe(
                jwk.x
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("x".to_string()))?,
            )?;
            let x_str = std::str::from_utf8(&x)?;
            let y = decode_base64_url_safe(
                jwk.y
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("y".to_string()))?,
            )?;
            let y_str = std::str::from_utf8(&y)?;
            Ok(DecodingKey::from_ec_components(x_str, y_str)?)
        }
        "HS256" | "HS384" | "HS512" => {
            let k = decode_base64_url_safe(
                jwk.k
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("k".to_string()))?,
            )?;
            Ok(DecodingKey::from_secret(&k))
        }
        alg => Err(TokenVerificationError::UnsupportedAlgorithm(
            alg.to_string(),
        )),
    }
}

fn decode_token(token: &str) -> Result<Claims, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }
    let payload = parts[1];
    let decoded_payload = decode_base64_url_safe(payload)?;
    let claims: Claims = serde_json::from_slice(&decoded_payload)?;
    Ok(claims)
}

fn verify_signature(
    token: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<bool, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = decode_base64_url_safe(parts[2])?;
    let signature_str = general_purpose::URL_SAFE_NO_PAD.encode(signature);

    match verify(&signature_str, message.as_bytes(), decoding_key, alg) {
        Ok(valid) => Ok(valid),
        Err(err) => {
            error!("Failed to verify signature: {:?}", err);
            Err(TokenVerificationError::from(err))
        }
    }
}

fn verify_token(opts: &Opts) -> Result<(Vec<String>, Claims), TokenVerificationError> {
    let header = jsonwebtoken::decode_header(&opts.token)?;
    info!("Full token header: {:?}", header);

    let kid = header
        .kid
        .ok_or(TokenVerificationError::MissingKeyComponent(
            "kid".to_string(),
        ))?;
    let alg = header.alg;

    info!("Algorithm from JWT header: {:?}", alg);

    let claims = decode_token(&opts.token)?;
    info!("Issuer from token: {}", claims.iss);
    let config = fetch_openid_configuration(&claims.iss)?;
    let jwks = fetch_jwks(&config.jwks_uri)?;

    let jwk = find_jwk(&jwks, &kid).ok_or(TokenVerificationError::NoMatchingKey)?;

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;
    debug!("Decoding key created");

    let mut summary = vec![];

    let signature_valid = verify_signature(&opts.token, &decoding_key, alg)?;
    if signature_valid {
        summary.push("Signature check: pass".to_string());
    } else {
        summary.push("Signature check: fail".to_string());
        println!("Signature check: Signature is not valid");
    }

    if let Some(ref client_id) = opts.client_id {
        if claims.aud == *client_id {
            summary.push("Audience check: pass".to_string());
        } else {
            summary.push("Audience check: fail".to_string());
            println!(
                "Audience check failed: expected: {}, actual: {}",
                client_id, claims.aud
            );
        }
    } else {
        summary.push("Audience(ClientId) check: skip".to_string());
    }

    if let Some(ref supplied_issuer) = opts.issuer {
        if claims.iss == *supplied_issuer {
            summary.push("Issuer check: pass".to_string());
        } else {
            summary.push("Issuer check: fail".to_string());
            println!(
                "Issuer check failed: expected: {}, actual: {}",
                supplied_issuer, claims.iss
            );
        }
    } else {
        summary.push("Issuer check: skip".to_string());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;

    if let Some(nbf) = claims.nbf {
        if now < nbf {
            summary.push("Not Before check: fail".to_string());
            println!(
                "Not Before check failed: Current time {} is before nbf {}",
                now, nbf
            );
        } else {
            summary.push("Not Before check: pass".to_string());
        }
    } else {
        summary.push("Not Before check: skip".to_string());
    }

    if now < claims.iat {
        summary.push("Expiration check: fail".to_string());
        println!(
            "Expiration check failed: Before effective period: now {} < issued at {}",
            now, claims.iat
        );
    } else if now > claims.exp {
        summary.push("Expiration check: fail".to_string());
        println!(
            "Expiration check failed: Token already expired: expires at {} < now {}",
            claims.exp, now
        );
    } else {
        summary.push("Expiration check: pass".to_string());
    }

    Ok((summary, claims))
}

fn main() -> Result<(), TokenVerificationError> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let (summary, claims) = verify_token(&opts)?;

    println!("\nSummary:");
    for line in &summary {
        println!(" {}", line);
    }

    println!("\nClaims in id_token: \n {:?}", claims);

    Ok(())
}
