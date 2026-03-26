#!/bin/bash
GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -o controller controller.go
