FROM golang:1.25-alpine

WORKDIR /app

# Configure Go to use the specific cache directory
ENV GOCACHE=/bin/.cache

RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./
# Use cache mount for module downloads
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Ensure the cache directory exists and is writable
RUN mkdir -p /bin/.cache

CMD ["air", "-c", ".air.toml"]
