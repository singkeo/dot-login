use std::{fmt, io};
use std::error::Error;
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::time::Duration;
use ark_bls12_381::{Bls12_381, Config, Fq};
use ark_ec::bls12::G1Affine;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use base64::Engine;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use uuid::Uuid;
use base64::engine::general_purpose::STANDARD;
use crc32fast::Hasher;
use num_bigint::{BigInt, Sign};
use rand::rngs::OsRng;
use ring::signature;
use ring::signature::KeyPair;
use serde_json::json;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::dynamic::tx;
use subxt::ext::scale_value::{Composite, value};
use subxt_signer::sr25519::dev;

const CLIENT_ID: &str = "801054035848-vn7773nujkjq17c2lcmc3en3doonfu8u.apps.googleusercontent.com";

fn read_file_to_string(filename: &str) -> String {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_) => contents,
        Err(_) => String::new(),
    }
}

#[derive(Serialize, Deserialize)]
struct KeyPairStruct {
    private_key: String,
    public_key: String,
}

fn save_key_pair_to_file(private_key: &str, public_key: &str) -> io::Result<()> {
    let key_pair = KeyPairStruct {
        private_key: private_key.to_string(),
        public_key: public_key.to_string(),
    };

    let file = File::create("last_key_pairs.json")?;
    serde_json::to_writer_pretty(file, &key_pair)?;

    Ok(())
}

fn read_key_pair_from_file() -> io::Result<KeyPairStruct> {
    let mut file = File::open("last_key_pairs.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let key_pair: KeyPairStruct = serde_json::from_str(&contents)?;

    Ok(key_pair)
}

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    n: String,
    #[serde(rename = "use")]
    #[allow(dead_code)]
    k_use: String,
    kid: String,
    #[allow(dead_code)]
    alg: String,
    #[allow(dead_code)]
    kty: String,
    e: String,
}

fn generate_ephemeral_key_pair() -> Result<(String, String), ring::error::Unspecified> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

    Ok((STANDARD.encode(key_pair.public_key().as_ref()), STANDARD.encode(pkcs8_bytes.as_ref())))
}

fn generate_nonce(public_key: &str) -> String {
    let randomness = Uuid::new_v4().to_string();

    let mut hasher = Hasher::new();
    hasher.update(randomness.as_bytes());
    hasher.update(public_key.as_bytes());
    let checksum = hasher.finalize();

    format!("{:x}", checksum)
}

fn generate_google_oauth2_url(redirect_uri: &str, nonce: &str) -> String {
    let params = [
        ("client_id", CLIENT_ID),
        ("response_type", "id_token"),
        ("redirect_uri", redirect_uri),
        ("scope", "openid email"),
        ("nonce", nonce),
    ];

    let encoded_params = serde_urlencoded::to_string(&params)
        .expect("Failed to encode query parameters");

    format!("https://accounts.google.com/o/oauth2/auth?{}", encoded_params)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    iss: String,
    // L'émetteur du token
    azp: String,
    // L'ID client autorisé
    aud: String,
    // Le destinataire du token, doit correspondre à l'ID client
    sub: String,
    // L'identifiant unique de l'utilisateur
    nonce: String,
    // Une chaîne utilisée pour associer une session client à un ID Token
    nbf: i64,
    // La date/heure avant laquelle le token n'est pas accepté (Not Before)
    iat: i64,
    // L'heure d'émission du token (Issued At)
    exp: i64,
    // L'heure d'expiration du token (Expire)
    jti: String,
    // Un identifiant unique pour le token (JWT ID)
    email: String,
}

impl fmt::Display for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\niss: {}\nazp: {}\naud: {}\nsub: {}\nnonce: {}\nnbf: {}\niat: {}\nexp: {}\njti: {}\nemail: {}\n",
            self.iss,
            self.azp,
            self.aud,
            self.sub,
            self.nonce,
            self.nbf,
            self.iat,
            self.exp,
            self.jti,
            self.email
        )
    }
}

async fn fetch_google_jwks_with_timeout(jwks_url: &str) -> Result<GoogleJwks, Box<dyn Error>> {
    let fallback_jwks = GoogleJwks {
        keys: vec![
            Jwk {
                alg: "RS256".to_string(),
                n: "rH3Q5NY6MAeaE8NuSw7Rw2Cc1e_j-kUS044tu-WcmTFzBKTuKvIlgj5w0SlSbiVl81zBtetQFtuwkMzWgnCks-2-Fwpoy__2NUouUgLtIggAVEyOGgPLfyaswtkSmZsUmWWg9J8CgMUdoXFkbZAPladDcmSqiXJ7cp9nvro6f4sjfrGDYz5_-SNz1AQEGbvcTh9EeZkvKPrmnV3YER95bJsgkHmNJVkQ6LcWtLyKhSGQGRMeTYaXDajc2KrKT3net7qNhbAm7KpWddbtR5l6A0TRCrAMoV2M68_GLRF24acj3UO5RW0SkuaBTZS4KQpyoyABCAtjLSr-3RY6WR9npw".to_string(),
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                k_use: "sig".to_string(),
                kid: "ed806f1842b588054b18b669dd1a09a4f367afc4".to_string(),
            },
            Jwk {
                alg: "RS256".to_string(),
                n: "pOpd5-7RpMvcfBcSjqlTNYjGg3YRwYRV9T9k7eDOEWgMBQEs6ii3cjcuoa1oD6N48QJmcNvAme_ud985DV2mQpOaCUy22MVRKI8DHxAKGWzZO5yzn6otsN9Vy0vOEO_I-vnmrO1-1ONFuH2zieziaXCUVh9087dRkM9qaQYt6QJhMmiNpyrbods6AsU8N1jeAQl31ovHWGGk8axXNmwbx3dDZQhx-t9ZD31oF-usPhFZtM92mxgehDqi2kpvFmM0nzSVgPrOXlbDb9ztg8lclxKwnT1EtcwHUq4FeuOPQMtZ2WehrY10OvsqS5ml3mxXUQEXrtYfa5V1v4o3rWx9Ow".to_string(),
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                k_use: "sig".to_string(),
                kid: "6f9777a685907798ef794062c00b65d66c240b1b".to_string(),
            },
        ],
    };

    match timeout(Duration::from_secs(2), reqwest::get(jwks_url)).await {
        Ok(Ok(response)) => {
            if response.status().is_success() {
                match response.json::<GoogleJwks>().await {
                    Ok(jwks) => Ok(jwks),
                    Err(_) => Ok(fallback_jwks),
                }
            } else {
                Ok(fallback_jwks)
            }
        }
        _ => Ok(fallback_jwks),
    }
}

async fn decode_google_jwt(token: &str) -> Result<Claims, Box<dyn Error>> {
    println!("Decoding {}", token);
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let jwks: GoogleJwks = fetch_google_jwks_with_timeout(jwks_url).await?;

    let header = jsonwebtoken::decode_header(token)?;

    let kid = header.kid.ok_or("Token header missing 'kid'")?;

    let jwk = jwks.keys.into_iter().find(|k| k.kid == kid).ok_or("Appropriate JWK not found")?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[CLIENT_ID]);
    validation.set_issuer(&["accounts.google.com"]);

    validation.insecure_disable_signature_validation();

    let token_data = decode::<Claims>(&token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

fn generate_user_salt(claims: &Claims) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&claims.iss);
    hasher.update(&claims.aud);
    hasher.update(&claims.sub);

    format!("{:x}", hasher.finalize())
}

fn get_extended_ephemeral_public_key(public_key: &str) -> Result<BigInt, Box<dyn Error>> {
    let bytes = STANDARD.decode(public_key)?;
    let bigint = BigInt::from_bytes_be(Sign::Plus, &bytes);
    Ok(bigint)
}

#[derive(Clone)]
struct ZkProofCircuit {
    pub a: Option<ark_bls12_381::Fr>,
    pub b: Option<ark_bls12_381::Fr>,
    pub c: Option<ark_bls12_381::Fr>,
}

impl ConstraintSynthesizer<ark_bls12_381::Fr> for ZkProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ark_bls12_381::Fr>) -> Result<(), SynthesisError> {
        #[allow(dead_code)]
        let a = cs.new_input_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        #[allow(dead_code)]
        let b = cs.new_input_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        #[allow(dead_code)]
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

        //TODO @Ahmed apply a constraint
        //cs.enforce_constraint();
        Ok(())
    }
}

fn point_to_b64(point: G1Affine<Config>) -> (String, String) {
    let mut x_bytes = vec![];
    let mut y_bytes = vec![];
    point.x.serialize_compressed(&mut x_bytes).unwrap();
    point.y.serialize_compressed(&mut y_bytes).unwrap();
    (STANDARD.encode(&x_bytes), STANDARD.encode(&y_bytes))
}

fn point_to_b64_2(point: &Fq) -> String {
    let mut vec = vec![];
    point.serialize_compressed(&mut vec).unwrap();
    STANDARD.encode(&vec)
}

fn generate_zk_proof(jwt_token: &str, extended_ephemeral_public_key: &str, salt: &str) -> String {
    let a_value = ark_bls12_381::Fr::from(jwt_token.as_bytes()[0]);
    let b_value = ark_bls12_381::Fr::from(extended_ephemeral_public_key.as_bytes()[0]);
    let c_value = ark_bls12_381::Fr::from(salt.as_bytes()[0]);

    let circuit = ZkProofCircuit {
        a: Some(a_value),
        b: Some(b_value),
        c: Some(c_value),
    };

    let rng = &mut OsRng;
    let params = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit.clone(), rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    let mut vk = vec![];
    pvk.serialize_compressed(&mut vk).unwrap();
    let vk_encoded = STANDARD.encode(&vk);

    let r = ark_bls12_381::Fr::rand(rng);
    let s = ark_bls12_381::Fr::rand(rng);

    let proof = Groth16::<Bls12_381>::create_proof_with_reduction(circuit, &params, r, s).unwrap();

    let (a_x, a_y) = point_to_b64(proof.a);
    let (b_x_c0, b_x_c1) = {
        let b_x = proof.b.x;
        (point_to_b64_2(&b_x.c0), point_to_b64_2(&b_x.c1))
    };
    let (b_y_c0, b_y_c1) = {
        let b_y = proof.b.y;
        (point_to_b64_2(&b_y.c0), point_to_b64_2(&b_y.c1))
    };
    let (c_x, c_y) = point_to_b64(proof.c);

    let mut hasher = Sha256::new();
    hasher.update(jwt_token.as_bytes());
    hasher.update(extended_ephemeral_public_key.as_bytes());
    hasher.update(salt.as_bytes());
    let public_hash = format!("{:x}", hasher.finalize());
    let public_hash_encoded = STANDARD.encode(public_hash);

    // Formater la sortie en JSON
    let json_output = json!({
        "a": {
            "x": a_x,
            "y": a_y
        },
        "b": {
            "x": {
                "c0": b_x_c0,
                "c1": b_x_c1
            },
            "y": {
                "c0": b_y_c0,
                "c1": b_y_c1
            }
        },
        "c": {
            "x": c_x,
            "y": c_y
        },
        "public_hash": public_hash_encoded,
        "verifying_key": vk_encoded,
        "jwt_token": jwt_token
    });

    return json_output.to_string();
}

#[tokio::main]
async fn main() {
    let token = read_file_to_string("current.jwt");

    println!();

    let pair_struct = read_key_pair_from_file();

    if token.is_empty() || pair_struct.is_err() {
        println!("Token/Key Pairs empty, Log first");
        start_log();
    } else {
        match decode_google_jwt(&token).await {
            Ok(claims) => {
                println!("Result Google JWT: {}\n", claims);

                let salt = generate_user_salt(&claims);
                println!("Generate salt for: {:?} based on iss, aud, sub -> {:?}\n", claims.email, salt);

                println!("Starting generate the ZkProof...");
                let extended_ephemeral_public_key = get_extended_ephemeral_public_key(&pair_struct.unwrap().public_key).unwrap().to_string();
                println!("1) Generating extended ephemeral public key -> {:?}\n", extended_ephemeral_public_key);
                let zk_proof = generate_zk_proof(&token, &extended_ephemeral_public_key, &salt);
                println!("2) Generating ZkProof -> {}\n", zk_proof);

                println!("Connecting to ParaChain...");
                let api = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await.unwrap();
                println!("Connection with ParaChain established.");

                let alice_pair_signer = dev::alice();

                println!("Submitting extrinsic...");
                let zk_proof_tx = tx("ZkProofModule", "store_zk_proof", Composite::unnamed([value! { (zk_proof.as_bytes().to_vec()) }]));

                let events = api.tx().sign_and_submit_then_watch_default(&zk_proof_tx, &alice_pair_signer).await
                    .map(|e| {
                        println!("Extrinsic submitted, waiting for transaction to be finalized...");
                        e
                    }).expect("Error while submitting extrinsic")
                    .wait_for_finalized_success()
                    .await.expect("Failed to finalize extrinsic...");
                println!("Extrinsic success: {:?}", events.extrinsic_hash());
            }
            Err(err) => {
                println!("Other error: {:?}", err);
                start_log();
            }
        }
    }
}

fn start_log() {
    let redirect_uri = "http://localhost";

    let key_pair = generate_ephemeral_key_pair().expect("Failed to generate Key Pair");
    let _ = save_key_pair_to_file(&key_pair.0, &key_pair.1);

    let nonce = generate_nonce(&key_pair.1);

    let auth_url = generate_google_oauth2_url(redirect_uri, &nonce);

    println!("Google OAuth login: {}", auth_url);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_key_pair_to_file() {
        let result = save_key_pair_to_file("private_key_test", "public_key_test");
        assert!(result.is_ok());

        let key_pair = read_key_pair_from_file().unwrap();
        assert_eq!(key_pair.private_key, "private_key_test");
        assert_eq!(key_pair.public_key, "public_key_test");
    }

    #[test]
    fn test_generate_nonce() {
        let public_key = "test_public_key";
        let nonce = generate_nonce(public_key);
        assert_eq!(nonce.len(), 8); // CRC32 produces a 8-character hexadecimal string
    }

    #[test]
    fn test_generate_google_oauth2_url() {
        let redirect_uri = "http://localhost";
        let nonce = "test_nonce";
        let url = generate_google_oauth2_url(redirect_uri, nonce);
        assert!(url.contains(CLIENT_ID));
        assert!(url.contains("response_type=id_token"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost"));
        assert!(url.contains("scope=openid+email"));
        assert!(url.contains("nonce=test_nonce"));
    }

    #[test]
    fn test_generate_user_salt() {
        let claims = Claims {
            iss: "issuer".to_string(),
            azp: "authorized_party".to_string(),
            aud: "audience".to_string(),
            sub: "subject".to_string(),
            nonce: "nonce".to_string(),
            nbf: 0,
            iat: 0,
            exp: 0,
            jti: "jwt_id".to_string(),
            email: "email@example.com".to_string(),
        };

        let salt = generate_user_salt(&claims);
        assert_eq!(salt, "2f92e1ca1c1a318145beb4a301c140ca079620730f6ce48f8bdb0d56091ff354");
    }
}
