# ---------- build stage (отключено) ----------
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS gobuilder
WORKDIR /app
RUN apk add --no-cache gcc musl-dev unbound-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o godns ./cmd

# ---------- final stage ----------
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata unbound mc
ENV TZ=""

COPY --from=gobuilder /app/godns /usr/local/bin/godns
COPY ./config/godns.yaml /etc/godns.yaml
COPY ./config/unbound.conf /etc/unbound/unbound.conf
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53 853

ENTRYPOINT ["/entrypoint.sh"]
#ENTRYPOINT ["/usr/local/bin/godns", "-c", "/etc/godns.yaml"]