# ---------- build stage (отключено) ----------
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS gobuilder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -installsuffix 'static' -o godns ./cmd

# ---------- final stage ----------
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata mc
ENV TZ=""

RUN mkdir -p /etc/godns

COPY --from=gobuilder /app/godns /usr/local/bin/godns
COPY ./config/godns.yaml /etc/godns.yaml
COPY ./config/default.local /etc/godns/default.local
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp

ENTRYPOINT ["/entrypoint.sh"]
