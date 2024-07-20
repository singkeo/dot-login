# DOT Login

The project consists of two services:

- `dot-login` client (this repo): here the ZKP is created
- [`dot-login-substrate-node`](https://github.com/singkeo/dot-login-substrate-node): here the ZKP is stored on-chain

## System Requirements

1. install essential tooling: `sudo apt install build-essential`
2. install pkg-config: `apt install pkg-config`
3. install libssl-dev: `sudo apt install libssl-dev`
4. install cargo: `curl https://sh.rustup.rs -sSf | sh`
5. use nightly toolchain: `rustup override set nightly`
6. verify toolchain: `rustup toolchain list`
    ```bash
    # expected output
    stable-x86_64-unknown-linux-gnu (default)
    nightly-x86_64-unknown-linux-gnu (override) # <-- verify that override is set to nightly toolchain
    ```

## Client Service

### Build

```bash
$ cargo build --release
```

### Run

1. Execute the client:
    ```bash
    $ cd ./target/release
    $ ./dot_login

      # output
      Token/Key Pairs empty, Log first
      Google OAuth login: https://accounts.google.com/o/oauth2/auth?client_id=801054035848-vn7773nujkjq17c2lcmc3en3doonfu8u.apps.googleusercontent.com&response_type=id_token&redirect_uri=http%3A%2F%2Flocalhost&scope=openid+email&nonce=8cb107f3
    ```
2. Copy the login URL into a browser
3. Log in with your gmail account. You should be redirected to `http://localhost/#id_token={JWT}` where `{JWT}` will represent your jwt.
4. Create the jwt config file: `touch current.jwt`
5. Open the file with an editor (e.g. `vi current.jwt`) and paste the jwt value into it (see step 3)
6. Execute the client again: `./dot_login`

    ```bash
    # output

    Decoding XXXX.YYYY.ZZZZ&authuser=0&prompt=consent&version_info=VVVV

    Result Google JWT: 
    iss: accounts.google.com
    azp: 801054035848-vn7773nujkjq17c2lcmc3en3doonfu8u.apps.googleusercontent.com
    aud: 801054035848-vn7773nujkjq17c2lcmc3en3doonfu8u.apps.googleusercontent.com
    sub: 110642249998642651331
    nonce: 8cb107f3
    nbf: 1716133413
    iat: 1716133713
    exp: 1716137313
    jti: aada3718ebc02e095535a71090df2743c91ed499
    email: user@mail.com


    Generate salt for: "user@mail.com" based on iss, aud, sub -> "abc"

    Starting generate the ZkProof...
    1) Generating extended ephemeral public key -> "123..."

    2) Generating ZkProof -> {
    "a": {
        "x": "0cb...",
        "y": "0d9..."
    },
    "b": {
        "x": {
        "c0": "173...",
        "c1": "173..."
        },
        "y": {
        "c0": "0a6...",
        "c1": "100..."
        }
    },
    "c": {
        "x": "020...",
        "y": "02f..."
    }
    }
    ```

7. Copy the JSON from step 3 and pass it to the substrate node by calling the extrinsic.

TODO: add more details

## Substrate Node

TODO: add link