# cert-updater

Simple tool to download certificates in secrets from kubernetes


## Usage

```
  cert-updater [flags]

Flags:
  -a, --apiserver-url string       API server URL (default "http://127.0.0.1:8001")
  -c, --ca-cert-file string        file containing the ca certificate for the api server (default "ca.crt")
  -C, --cert-file string           file to store the certificate (default "tls.crt")
  -h, --help                       help for cert-updater
  -K, --key-file string            file to store the key (default "tls.key")
  -n, --namespace string           namespace for the secret (default "default")
  -p, --post-update-hook strings   shell command to run after a successful certificate update
  -t, --token-file string          file containing the bearer token (default "token")
      --version                    version for cert-updater
```
