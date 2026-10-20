FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY static ./static
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/markdown-notes .

FROM alpine:3.22
ENV PORT=8080 DATABASE_PATH=/data/notes.db
RUN addgroup -g 10001 app && adduser -D -H -u 10001 -G app app && mkdir /data && chown app:app /data
COPY --from=build --chown=app:app /out/markdown-notes /usr/local/bin/markdown-notes
USER app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -T 2 -O /dev/null http://127.0.0.1:8080/health/ready || exit 1

CMD ["markdown-notes"]
