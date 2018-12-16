package secenv

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	prefix = "VAULT:"
)

var (
	// Package level structure with simple access via secenv.Get() function
	global        *SecEnv
	defaultConfig Config

	ErrNoTokenProvided = NewError("no token provided")
	ErrNoDataReturned  = NewError("no data returned")
	ErrWrongValueType  = NewError("wrong value type")
)

func init() {
	defaultConfig = Config{
		addr:  os.Getenv("VAULT_ADDR"),
		token: os.Getenv("VAULT_TOKEN"),
		client: &http.Client{
			Timeout: 250 * time.Millisecond,
		},
	}

	global = NewSecEnv(&defaultConfig)
}

type Secret struct {
	// The request ID that generated this response
	RequestID string `json:"request_id"`

	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`

	// Data is the actual contents of the secret. The format of the data
	// is arbitrary and up to the secret backend.
	Data map[string]interface{} `json:"data"`

	// Warnings contains any warnings related to the operation. These
	// are not issues that caused the command to fail, but that the
	// client should be aware of.
	Warnings []string `json:"warnings"`
}

type SecEnv struct {
	cfg Config
}

type Config struct {
	addr   string
	token  string
	client *http.Client
}

// SecEnv constructor
func NewSecEnv(cfg *Config) *SecEnv {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.addr == "" {
		cfg.addr = defaultConfig.addr
	}

	if cfg.token == "" {
		cfg.token = defaultConfig.token
	}

	if cfg.client == nil {
		cfg.client = defaultConfig.client
	}

	return &SecEnv{cfg: *cfg}
}

// Get secret from vault with settings based on environment variables
func Get(name string) (string, error) {
	return global.Get(name)
}

// Get secret from vault
func (se *SecEnv) Get(name string) (string, error) {
	value := os.Getenv(name)

	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}

	if se.cfg.token == "" {
		return "", ErrNoTokenProvided
	}

	value = strings.TrimPrefix(value, prefix)
	path, field := splitName(value)

	response, err := se.request("GET", filepath.Join("/v1/secret", path), nil)
	if err != nil {
		return "", err
	}

	var secret Secret
	if err = se.parse(response, &secret); err != nil {
		return "", err
	}

	if secret, ok := secret.Data[field]; ok {
		switch secret.(type) {
		case string:
			return secret.(string), nil
		case int:
			return strconv.FormatInt(int64(secret.(int)), 10), nil
		default:
			return "", ErrWrongValueType
		}
	} else {
		return "", ErrNoDataReturned
	}
}

// Requests to vault via http.Client
func (se *SecEnv) request(verb, path string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(verb, se.cfg.addr+path, body)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(path, "/v1/secret") {
		request.Header.Set("X-Vault-token", se.cfg.token)
	}

	response, err := se.cfg.client.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Response parsing into Secret structure
func (se *SecEnv) parse(response *http.Response, secret *Secret) error {
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if err = json.Unmarshal(body, secret); err != nil {
		return err
	}

	return nil
}

// Split full vault path into two pieces. First piece is path to the secret "path/to/test" and second piece is key name
// "something" of secret. One secret may contain many keys and values. Default key name is "value".
// VAULT:path/to/test.something.
func splitName(value string) (path, field string) {
	switch v := strings.SplitN(value, ".", 2); len(v) {
	case 2:
		path = v[0]
		field = v[1]
	default:
		path = v[0]
		field = "value"
	}

	return
}
