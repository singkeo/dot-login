# DOT Login

![web3 foundation_grants_badge_black](https://github.com/user-attachments/assets/3c628f6d-36ef-4b18-bb9f-c96ec8a33a63)

The project consists of two services:

- `dot-login` client (this repo): here the ZKP is created
- [`dot-login-substrate-node`](https://github.com/singkeo/dot-login-substrate-node): here the ZKP is stored on-chain

## System Requirements

Currently, Linux-based operating systems are supported (e.g. Ubuntu).

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

### Docker

#### Build Docker image

```
docker build -t dot-login-client .
docker image ls
```

expected output:
```
# docker image ls
REPOSITORY          TAG       IMAGE ID       CREATED       SIZE
dot-login-client    latest    ec2046278f3f   5 hours ago   8.07GB
```


#### Run Docker container

1. Run the container in interactive mode (`/bin/bash`) in order to follow the tutorial:

    ```
    docker run -it --rm rust-dot-login /bin/bash
    ```

2. Inside the container, you can run the application and follow the manual steps to complete the login process and generate the ZKP.

    ```
    cd ./target/release
    ./dot_login
    ```

3. Copy the login URL into a browser, log in with your gmail account, and get redirected to http://localhost/#id_token={JWT} where {JWT} represents your JWT. Copy the URL into an editor and extract the JWT, this will be neede for the next step.

4. **Create JWT Config File:** Create a JWT config file and paste the JWT value.

    ```
    touch current.jwt
    vi current.jwt
    ```

5. Run the Client Again: Execute the client again with the JWT.

    ```
    ./dot_login
    ```

6. **Submit ZKP to Substrate Node:** Copy the generated JSON and pass it to the substrate node by calling the extrinsic.

### Local

#### Build

```bash
$ cargo build --release
```

#### Run

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

7. Copy the JSON from step 3 and pass it to the substrate node by calling the `zkProofModule.storeZkProof` extrinsic.


## Substrate Node

1. Get the node up & running

    ```bash
    # 1) clone node repo
    git clone git@github.com:singkeo/dot-login-substrate-node.git

    # 2) build node
    cargo build --release

    # 3) start node (note: add --unsafe-rpc-external if you're planning to access it the node from a remote machine)
    ./target/release/node-template --dev
    ```

2. you can now submit the zk proof that you've generated in the client to the blockchain (see previous step)