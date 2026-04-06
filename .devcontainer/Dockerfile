FROM docker.io/rust:1-slim-trixie


# Install development dependencies
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
    build-essential pkg-config musl-tools ca-certificates man-db \
    neovim less git curl wget unzip ripgrep locales file procps net-tools \
    bubblewrap socat \
    protobuf-compiler \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Locale setup
RUN echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen \
 && locale-gen en_US.UTF-8 \
 && update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Create non-root user
RUN groupadd -r dev -g 1000 \
 && useradd -r -g dev -u 1000 -d /home/dev -s /bin/bash dev \
 && mkdir /home/dev && chown dev:dev /home/dev

# Create directories with user ownership
# Note: VS Code Dev Containers will automatically adjust UID/GID via updateRemoteUserUID
RUN mkdir -p /code && chown dev:dev /code

# Switch to non-root user
USER dev

# Install Rust dev components
RUN rustup component add rustfmt clippy
RUN cargo install cargo-insta cargo-audit

# Create persistent config directory with default ownership
RUN mkdir -p ~/.config-persistent/

# Create Claude Code directories with default ownership
RUN mkdir -p ~/.config/claude/

# Create OpenCode directories with default ownership
RUN mkdir -p ~/.config/opencode/ \
 && mkdir -p ~/.local/share/opencode/

ENTRYPOINT ["/bin/bash"]
