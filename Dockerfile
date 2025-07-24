# ---------- build stage (отключено) ----------
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS gobuilder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o godns ./cmd

# ---------- final stage ----------
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata mc
ENV TZ=""

COPY --from=gobuilder /app/godns /usr/local/bin/godns
COPY ./config/godns.yaml /etc/godns.yaml
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 853/tcp

ENTRYPOINT ["/entrypoint.sh"]
