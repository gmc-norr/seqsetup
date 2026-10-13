FROM ghcr.io/prefix-dev/pixi:latest AS build

WORKDIR /app

# The Tailwind install (pixi run css, below) downloads with curl, which the pixi
# base image does not have. What it downloads is checked against
# tools/tailwind-sha256.txt before it is made executable.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for layer caching. Only the default environment
# is installed: the test, browser and docs tools are in the `dev` environment
# (pixi.toml), so none of them ships to the lab.
COPY pixi.toml pixi.lock ./
RUN pixi install --locked --environment default

# Copy application source and config
COPY src/ src/
COPY tools/ tools/
COPY tailwind.config.js ./
COPY config/ config/

EXPOSE 5001

# Build Tailwind CSS so the image ships with the generated app.css.
# The pixi css task is gated behind tailwind-install which downloads the
# pinned standalone binary into .pixi/bin/ and checks its SHA-256
# (tools/install-tailwind.sh); a binary that does not match stops the build.
RUN pixi run css

# Drop root for the runtime process (defense in depth — a process compromise
# then lands unprivileged, can't overwrite the app source, and has a harder
# path to container escape). Created AFTER the build steps so pixi
# install/css run as root; ownership of /app (incl. the .pixi env and any
# runtime-written .sesskey when no SEQSETUP_SESSION_SECRET is set) is handed
# to the runtime user.
RUN groupadd --system --gid 10001 seqsetup \
 && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin seqsetup \
 && chown -R seqsetup:seqsetup /app
USER seqsetup

CMD ["pixi", "run", "serve"]
