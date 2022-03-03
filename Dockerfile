# syntax=docker/dockerfile:1

FROM golang:1.17-alpine AS build

WORKDIR /app

COPY go.mod go.su[m] ./

RUN go mod download

COPY . ./

RUN go build -o /vault

FROM scratch

COPY --from=build /vault /vault

CMD ["/vault"]