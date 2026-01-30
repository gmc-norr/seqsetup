FROM ghcr.io/prefix-dev/pixi:latest AS build

WORKDIR /app

# Copy dependency files first for layer caching
COPY pixi.toml pixi.lock ./
RUN pixi install --locked

# Copy application source and config
COPY src/ src/
COPY config/ config/

EXPOSE 5001

CMD ["pixi", "run", "serve"]
