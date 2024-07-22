# Use the official Ubuntu 22.04 image as the base image
FROM ubuntu:22.04

# Install required dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the source code into the container
COPY . .

# Install the nightly toolchain and set it as default
RUN rustup toolchain install nightly && \
    rustup override set nightly

# Build the Rust project
RUN cargo build --release

# Run the application
CMD ["./target/release/dot_login"]
