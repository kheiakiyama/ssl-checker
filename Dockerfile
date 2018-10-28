FROM golang:latest

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
WORKDIR /go/src/github.com/kheiakiyama/ssl-checker
COPY . .
RUN dep ensure 
RUN CGO_ENABLED=0 GOOS=linux go build

FROM alpine:latest
COPY --from=0 /go/src/github.com/kheiakiyama/ssl-checker/ssl-checker .
CMD ["./ssl-checker", "-h"]
