package secenv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	prefix = "VAULT:"

	authKubernetes      = "kubernetes"
	kubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

var (
	// Package level structure with simple access via secenv.Get() function
	global        *SecEnv
	defaultConfig Config
)

func init() {
	defaultConfig = Config{
		service: os.Getenv("SERVICE_NAME"),
		addr:    os.Getenv("VAULT_ADDR"),
		token:   os.Getenv("VAULT_TOKEN"),
		auth: &Auth{
			mu:        &sync.Mutex{},
			method:    os.Getenv("VAULT_AUTH"),
			tokenPath: "",
			expireAt:  time.Now(),
		},
		client: &http.Client{
			Timeout: 250 * time.Millisecond,
		},
	}

	if defaultConfig.auth.method == authKubernetes {
		defaultConfig.auth.tokenPath = kubernetesTokenPath
	}

	global = NewSecEnv(&defaultConfig)
}

type Secret struct {
	// Data is the actual contents of the secret. The format of the data
	// is arbitrary and up to the secret backend.
	Data map[string]map[string]any `json:"data"`

	// Auth, if non-nil, means that there was authentication information
	// attached to this response.
	Auth *SecretAuth `json:"auth,omitempty"`
}

// SecretAuth is the structure containing auth information if we have it.
type SecretAuth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
}

type SecEnv struct {
	cfg Config
}

type Config struct {
	service string
	addr    string
	token   string
	auth    *Auth
	client  *http.Client
}

type Auth struct {
	mu        *sync.Mutex
	method    string
	tokenPath string
	expireAt  time.Time
}

type LoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// SecEnv constructor
func NewSecEnv(cfg *Config) *SecEnv {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.service == "" {
		cfg.service = defaultConfig.service
	}

	if cfg.addr == "" {
		cfg.addr = defaultConfig.addr
	}

	if cfg.token == "" {
		cfg.token = defaultConfig.token
	}

	if cfg.auth == nil {
		cfg.auth = defaultConfig.auth
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

	if se.cfg.auth.method == authKubernetes {
		err := se.auth()
		if err != nil {
			return "", fmt.Errorf("secenv(%s): %w", name, err)
		}
	}

	if se.cfg.token == "" {
		return "", fmt.Errorf("no token provided")
	}

	value = strings.TrimPrefix(value, prefix)
	path, field := splitName(value)

	response, err := se.request("GET", filepath.Join("/v1/secret/data", path), nil)
	if err != nil {
		return "", fmt.Errorf("secenv(%s): %w", name, err)
	}

	var secret Secret
	if err = se.parse(response, &secret); err != nil {
		return "", fmt.Errorf("secenv(%s): %w", name, err)
	}

	var innerData map[string]any
	var ok bool

	if innerData, ok = secret.Data["data"]; !ok {
		return "", fmt.Errorf("no second level data was found")
	}

	if secret, ok := innerData[field]; ok {
		switch secret.(type) {
		case string:
			return secret.(string), nil
		case int:
			return strconv.FormatInt(int64(secret.(int)), 10), nil
		default:
			return "", fmt.Errorf("secenv(%s): %s", name, "wrong value type")
		}
	} else {
		return "", fmt.Errorf("secenv(%s): %s", name, "no data returned")
	}
}

// Requests to vault via http.Client
func (se *SecEnv) request(verb, path string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(verb, se.cfg.addr+path, body)
	if err != nil {
		return nil, fmt.Errorf("building request error: %w", err)
	}

	if strings.HasPrefix(path, "/v1/secret") {
		request.Header.Set("X-Vault-token", se.cfg.token)
	}

	response, err := se.cfg.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doing remote request error: %w", err)
	}

	return response, nil
}

// Authentication with Kubernetes token
func (se *SecEnv) auth() error {
	se.cfg.auth.mu.Lock()
	defer se.cfg.auth.mu.Unlock()

	now := time.Now()

	if se.cfg.auth.expireAt.Before(now) || se.cfg.auth.expireAt.Equal(now) {
		jwt, err := os.ReadFile(se.cfg.auth.tokenPath)
		if err != nil {
			return fmt.Errorf("read token file error: %w", err)
		}

		login := LoginRequest{
			Role: se.cfg.service,
			JWT:  string(jwt),
		}

		loginJson, err := json.Marshal(login)
		if err != nil {
			return fmt.Errorf("marshalling json error: %w", err)
		}

		response, err := se.request("PUT", "/v1/auth/kubernetes/login", bytes.NewReader(loginJson))
		if err != nil {
			return fmt.Errorf("kubernetes auth request error: %w", err)
		}

		var secret Secret
		err = se.parse(response, &secret)
		if err != nil {
			return fmt.Errorf("parsing kubernetes auth response error: %w", err)
		}

		se.cfg.token = secret.Auth.ClientToken
		se.cfg.auth.expireAt = now.Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	}

	return nil
}

// Response parsing into Secret structure
func (se *SecEnv) parse(response *http.Response, secret *Secret) error {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading body error: %w", err)
	}
	defer response.Body.Close()

	if err = json.Unmarshal(body, secret); err != nil {
		return fmt.Errorf("unmarshalling error: %w", err)
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
