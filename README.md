## Getting Started

### 1. Start OWASP ZAP using Docker

Run the following command to start the ZAP server in a Docker container:

```sh
docker run --name zap -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

### 2. Run the CLI tool


You can run the CLI tool using:

```sh
go run cmd/main.go --target https://www.unsaac.edu.pe --output out.json --timeout 10
```

- Replace the `--target` value with the URL you want to scan. It is required
- The `--output` flag specifies the file where the scan result will be saved. It is optional.
- The `--timeout` flag sets the maximum scan duration in seconds before the process is canceled. It is optional.
- The `--user` flag sets the user for authenticate. Should be together with the password flag. It is optional.
- The `--password` flag sets the password for authenticate. Should be together with the user flag. It is optional.
- The `--type` flag sets the type of scan. By default is active. We can specify to be passive. It is optional.
