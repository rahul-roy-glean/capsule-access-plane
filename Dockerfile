FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /capsule-access-plane .

FROM gcr.io/distroless/static-debian12

COPY --from=builder /capsule-access-plane /capsule-access-plane

EXPOSE 8080

ENTRYPOINT ["/capsule-access-plane"]
