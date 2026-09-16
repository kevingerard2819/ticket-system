FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o ticket-system .

FROM alpine:3.20

WORKDIR /app
COPY --from=build /app/ticket-system /app/ticket-system

ENV PORT=8080
EXPOSE 8080

CMD ["/app/ticket-system"]
