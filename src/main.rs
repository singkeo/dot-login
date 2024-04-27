use std::{fmt, io};
use std::error::Error;
use std::fmt::{Debug, Pointer};
use std::fs::File;
use std::io::Read;
use std::ptr::null;
use std::time::Duration;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use uuid::Uuid;
use base64::{Engine as _, encode, Engine};
use base64::engine::general_purpose::STANDARD;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use bellperson::gadgets::boolean::Boolean;
use bellperson::gadgets::multipack;
use bellperson::gadgets::sha256::sha256;
use bellperson::groth16::{create_random_proof, generate_random_parameters, Proof};
use blstrs::{Bls12, Fp, Scalar};
use crc32fast::Hasher;
use ff::PrimeField;
use num_bigint::{BigInt, Sign};
use rand::rngs::OsRng;
use ring::signature;
use ring::signature::KeyPair;
use serde_json::{json, Value};
use sp_keyring::AccountKeyring;
use substrate_api_client::ac_primitives::{AssetRuntimeConfig};
use substrate_api_client::{Api, GetChainInfo, SubmitAndWatch, SubmitExtrinsic, SystemApi, XtStatus};
use substrate_api_client::ac_compose_macros::{compose_call, compose_extrinsic};
use substrate_api_client::ac_node_api::Metadata;
use substrate_api_client::rpc::Error::Client;
use substrate_api_client::rpc::WsRpcClient;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::config::polkadot;
use subxt::dynamic::tx;
use subxt::ext::scale_value::{Composite, Primitive, value};
use subxt::runtime_api::Payload;
use subxt::utils::{AccountId32, MultiAddress};
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
    k_use: String,
    kid: String,
    alg: String,
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
    email: String, // Email de l'utilisateur
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

    validation.insecure_disable_signature_validation(); //todo remove on production

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

fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
    let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

    // Flip endianness of each output byte
    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

fn prepare_input_data<Scalar: PrimeField>(data: &str) -> Vec<Boolean> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_result = hasher.finalize();

    // Convert the hash result to bits in little-endian format
    hash_result
        .iter()
        .flat_map(|byte| (0..8).map(move |i| Boolean::constant((byte >> i) & 1u8 == 1u8)))
        .collect()
}

struct MyCircuit {
    jwt_token_data: Vec<Boolean>,
    extended_ephemeral_public_key_data: Vec<Boolean>,
    salt_data: Vec<Boolean>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Hash each input separately
        let jwt_token_hash = sha256(cs.namespace(|| "SHA-256(jwt_token)"), &self.jwt_token_data)?;
        let extended_ephemeral_public_key_hash = sha256(cs.namespace(|| "SHA-256(extended_ephemeral_public_key)"), &self.extended_ephemeral_public_key_data)?;
        let salt_hash = sha256(cs.namespace(|| "SHA-256(salt)"), &self.salt_data)?;

        // Combine the hashes into a single vector
        let combined_hash = [jwt_token_hash, extended_ephemeral_public_key_hash, salt_hash].concat();

        // Optionally, you can hash them again or directly expose them as public inputs
        let final_hash = sha256d(cs.namespace(|| "SHA-256(combined_hash)"), &combined_hash)?;

        // Expose the final hash as compact public inputs
        multipack::pack_into_inputs(cs.namespace(|| "pack final hash"), &final_hash)
    }
}

fn coord_to_hex(coord: &Fp) -> String {
    let bytes = coord.to_bytes_be();
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn proof_to_json(proof: Proof<Bls12>) -> Value {
    let a_x = coord_to_hex(&proof.a.x());
    let a_y = coord_to_hex(&proof.a.y());

    let b_x_c0 = coord_to_hex(&proof.b.x().c0());
    let b_x_c1 = coord_to_hex(&proof.b.x().c0());
    let b_y_c0 = coord_to_hex(&proof.b.y().c0());
    let b_y_c1 = coord_to_hex(&proof.b.y().c1());

    let c_x = coord_to_hex(&proof.c.x());
    let c_y = coord_to_hex(&proof.c.y());

    json!({
        "a": {"x": a_x, "y": a_y},
        "b": {
            "x": {"c0": b_x_c0, "c1": b_x_c1},
            "y": {"c0": b_y_c0, "c1": b_y_c1},
        },
        "c": {"x": c_x, "y": c_y}
    })
}

fn generate_zk_proof(jwt_token: &str, extended_ephemeral_public_key: &str, salt: &str) -> String {
    let circuit = MyCircuit {
        jwt_token_data: prepare_input_data::<Scalar>(jwt_token),
        extended_ephemeral_public_key_data: prepare_input_data::<Scalar>(extended_ephemeral_public_key),
        salt_data: prepare_input_data::<Scalar>(salt),
    };

    let rng = &mut OsRng;

    let params = {
        let c = MyCircuit { jwt_token_data: vec![], extended_ephemeral_public_key_data: vec![], salt_data: vec![] };
        generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };

    let proof = create_random_proof(circuit, &params, rng).unwrap();

    return serde_json::to_string_pretty(&proof_to_json(proof)).unwrap();
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

                let alice: MultiAddress<AccountId32, ()> = dev::alice().public_key().into();
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