FROM convox/golang

WORKDIR $GOPATH/src/github.com/convox/certbot
COPY . .
RUN go install .

CMD ["bin/web"]
