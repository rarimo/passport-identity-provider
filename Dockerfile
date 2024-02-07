FROM golang:1.20-alpine as buildbase

RUN apk add git build-base

WORKDIR /go/src/github.com/RarimoVoting/identity-provider-service
COPY vendor .
COPY . .

RUN GOOS=linux go build  -o /usr/local/bin/identity-provider-service /go/src/github.com/RarimoVoting/identity-provider-service


FROM alpine:3.9

COPY --from=buildbase /usr/local/bin/identity-provider-service /usr/local/bin/identity-provider-service
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["identity-provider-service"]
