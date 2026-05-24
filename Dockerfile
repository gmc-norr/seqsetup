FROM ghcr.io/prefix-dev/pixi:latest AS build

WORKDIR /app

# Copy dependency files first for layer caching
COPY pixi.toml pixi.lock ./
RUN pixi install --locked

# Copy application source and config
COPY src/ src/
COPY tools/ tools/
COPY tailwind.config.js ./
COPY config/ config/

EXPOSE 5001

# Build Tailwind CSS so the image ships with the generated app.css.
# The pixi css task is gated behind tailwind-install which downloads the
# pinned standalone binary into .pixi/bin/.
RUN pixi run css

CMD ["pixi", "run", "serve"]
