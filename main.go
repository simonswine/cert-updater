package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
)

var config = &Config{}

var versionString = "unknown"
var versionCommit = ""

// Config represents config of the updater
type Config struct {
	SecretName    string
	Namespace     string
	APIServer     string
	CACertificate string
	Token         string

	CertificateFile string
	KeyFile         string

	PostUpdateHook []string
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&config.CACertificate, "ca-cert-file", "c", "ca.crt", "file containing the ca certificate for the api server")
	rootCmd.PersistentFlags().StringVarP(&config.Token, "token-file", "t", "token", "file containing the bearer token")
	rootCmd.PersistentFlags().StringVarP(&config.Namespace, "namespace", "n", "default", "namespace for the secret")
	rootCmd.PersistentFlags().StringVarP(&config.APIServer, "apiserver-url", "a", "http://127.0.0.1:8001", "API server URL")
	rootCmd.PersistentFlags().StringVarP(&config.CertificateFile, "cert-file", "C", "tls.crt", "file to store the certificate")
	rootCmd.PersistentFlags().StringVarP(&config.KeyFile, "key-file", "K", "tls.key", "file to store the key")
	rootCmd.PersistentFlags().StringSliceVarP(&config.PostUpdateHook, "post-update-hook", "p", []string{}, "shell command to run after a successful certificate update")
	if len(versionCommit) > 0 {
		rootCmd.Version = fmt.Sprintf("%s commit=%s", versionString, versionCommit)
	} else {
		rootCmd.Version = versionString
	}
}

type myRoundTripper struct {
	r http.RoundTripper
}

// RoundTrip implements http.RoundTripper
func (r *myRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", fmt.Sprintf("simonswine-cert-updater/%s", versionString))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", config.Token))
	return r.r.RoundTrip(req)
}

var rootCmd = &cobra.Command{
	Use:   "cert-updater",
	Short: "Simple tool to download certificates in secrets from kubernetes",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("please provide a secret name as argument")
		}

		config.SecretName = args[0]

		caCert, err := ioutil.ReadFile(config.CACertificate)
		if err != nil {
			log.Fatal("error reading ca certificate file: ", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		token, err := ioutil.ReadFile(config.Token)
		if err != nil {
			log.Fatal("error reading token file: ", err)
		}
		config.Token = strings.TrimSpace(string(token))

		client := &http.Client{
			Transport: &myRoundTripper{
				r: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: caCertPool,
					},
				},
			},
		}

		resp, err := client.Get(fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", config.APIServer, config.Namespace, config.SecretName))
		if err != nil {
			log.Println(err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("invalid status %d", resp.StatusCode)
			}
			log.Fatalf("invalid status %d\nbody = %s", resp.StatusCode, body)
		}

		secret := struct {
			Kind string
			Type string
			Data map[string]string
		}{}

		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&secret); err != nil {
			log.Fatalf("error decoding json: %s", err)
		}

		if exp, act := "kubernetes.io/tls", secret.Type; exp != act {
			log.Fatalf("unexpected secret type exp=%s act=%s", exp, act)
		}

		existingKey, err := ioutil.ReadFile(config.KeyFile)
		if err != nil {
			existingKey = []byte{}
		}

		existingCertificate, err := ioutil.ReadFile(config.CertificateFile)
		if err != nil {
			existingCertificate = []byte{}
		}

		updated := false

		if base64Data, ok := secret.Data["tls.key"]; ok {
			key, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				log.Fatalf("error decoding key: %s", err)
			}

			if !reflect.DeepEqual(key, existingKey) {
				err = ioutil.WriteFile(config.KeyFile, key, 0600)
				if err != nil {
					log.Fatalf("error writing key: %s", err)
				}
				updated = true
			}
		}

		if base64Data, ok := secret.Data["tls.crt"]; ok {
			crt, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				log.Fatalf("error decoding cert: %s", err)
			}

			if !reflect.DeepEqual(crt, existingCertificate) {
				err = ioutil.WriteFile(config.CertificateFile, crt, 0644)
				if err != nil {
					log.Fatalf("error writing cert: %s", err)
				}
				updated = true
			}
		}

		if updated {
			log.Printf("certificate updated")
			if len(config.PostUpdateHook) != 0 {
				log.Printf("running post-update-hook %v", config.PostUpdateHook)
				cmd := exec.Command(config.PostUpdateHook[0], config.PostUpdateHook[1:]...)
				err := cmd.Run()
				if err != nil {
					log.Fatalf("error running post-update-hook: %s", err)
				}
			}
		} else {
			log.Printf("certificate matches, no update necessary")
		}
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
