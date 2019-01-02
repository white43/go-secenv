package secenv

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	secEnvName       = "SECENV_TEST"
	secEnvValue      = prefix + "test"
	secEnvFieldValue = prefix + "test.field"
	expected         = "Ololo"
)

// Read environment variable without request to vault.
func TestSecEnv_Get(t *testing.T) {
	env := NewSecEnv(nil)

	err := os.Setenv(secEnvName, expected)
	if err != nil {
		t.Error(err)
	}

	value, err := env.Get(secEnvName)
	if err != nil {
		t.Error(err)
	}

	if value != expected {
		t.Errorf("expected \"%s\", got %s", expected, value)
	}
}

// Read environment variable with request to vault using default key name "value".
func TestSecEnv_GetSecretValue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//noinspection GoUnhandledErrorResult
		fmt.Fprintf(w, `{"data":{"value":"%s"}}`, expected)
	}))
	defer ts.Close()

	env := NewSecEnv(&Config{
		token: "test",
		addr:  ts.URL,
	})

	err := os.Setenv(secEnvName, secEnvValue)
	value, err := env.Get(secEnvName)
	if err != nil {
		t.Errorf("expected value, got error %#v", err)
	}

	if value != expected {
		t.Errorf("expected \"%s\", got %s", expected, value)
	}
}

// Read environment variable with request to vault using user defined key name "field" instead of default "value".
func TestSecEnv_GetSecretValueCustomField(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//noinspection GoUnhandledErrorResult
		fmt.Fprintf(w, `{"data":{"field":"%s"}}`, expected)
	}))
	defer ts.Close()

	env := NewSecEnv(&Config{
		token: "test",
		addr:  ts.URL,
	})

	err := os.Setenv(secEnvName, secEnvFieldValue)
	value, err := env.Get(secEnvName)
	if err != nil {
		t.Errorf("expected value value, got error %#v", err)
	}

	if value != expected {
		t.Errorf("expected \"%s\", got %s", expected, value)
	}
}

// Read environment variable with no token provided.
func TestSecEnv_GetNoTokenProvidedError(t *testing.T) {
	env := NewSecEnv(&Config{
		token: "",
	})

	err := os.Setenv(secEnvName, secEnvValue)
	if err != nil {
		t.Error(err)
	}

	_, err = env.Get(secEnvName)
	if err == nil {
		t.Error("expected secenv error, got <nil>")
	}

	switch err := errors.Cause(err).(type) {
	case *Error:
		if err.msg != noTokenProvided {
			t.Errorf("expected secenv error, got error %#v", err)
		}
	default:
		t.Errorf("expected secenv error, got error %#v", err)
	}
}

// Read environment variable with wrong vault address.
func TestSecEnv_GetUrlError(t *testing.T) {
	env := NewSecEnv(&Config{
		token: "test",
		addr:  "http://127.0.0.2:8200",
	})

	err := os.Setenv(secEnvName, secEnvValue)
	if err != nil {
		t.Error(err)
	}

	_, err = env.Get(secEnvName)
	if err == nil {
		t.Error("expected url error, got <nil>")
	}

	switch errors.Cause(err).(type) {
	case *url.Error:
		// ok
	default:
		t.Errorf("expected url error, got error %#v", err)
	}
}

// Read environment variable with unexpected answer from vault service
func TestSecEnv_GetResponseUnmarshalError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//noinspection GoUnhandledErrorResult
		fmt.Fprintln(w, `wat`)
	}))
	defer ts.Close()

	env := NewSecEnv(&Config{
		token: "test",
		addr:  ts.URL,
	})

	err := os.Setenv(secEnvName, secEnvValue)
	_, err = env.Get(secEnvName)

	if err == nil {
		t.Error("expected json syntax error, got <nil>")
	}

	switch errors.Cause(err).(type) {
	case *json.SyntaxError:
		// ok
	default:
		t.Errorf("expected json syntax error, got error %#v", err)
	}
}

// Read environment variable with empty data from vault service
func TestSecEnv_GetNoDataProvidedError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//noinspection GoUnhandledErrorResult
		fmt.Fprintln(w, `{"data":{}}`)
	}))
	defer ts.Close()

	env := NewSecEnv(&Config{
		token: "test",
		addr:  ts.URL,
	})

	err := os.Setenv(secEnvName, secEnvValue)
	_, err = env.Get(secEnvName)

	if err == nil {
		t.Error("expected secenv error, got <nil>")
	}

	switch err := errors.Cause(err).(type) {
	case *Error:
		if err.msg != noDataReturned {
			t.Errorf("expected secenv error, got error %#v", err)
		}
	default:
		t.Errorf("expected secenv error, got error %#v", err)
	}
}

// Reading environment variable with Kubernetes authentication
func TestSecEnv_GetErrCantReadTokenFile(t *testing.T) {
	env := NewSecEnv(&Config{
		token: "test",
		auth: &Auth{
			mu:     &sync.Mutex{},
			method: authKubernetes,
		},
	})

	err := os.Setenv(secEnvName, secEnvValue)
	_, err = env.Get(secEnvName)

	if err == nil {
		t.Error("expected *os.PathError error, got <nil>")
	}

	switch errors.Cause(err).(type) {
	case *os.PathError:
		// ok
	default:
		t.Errorf("expected *os.PathError, got %+v", err)
	}
}

// Read environment variable with request to vault using default key name "value" and Kubernetes authentication.
func TestSecEnv_GetSecretValueWithKubernetesAuthentication(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			//noinspection GoUnhandledErrorResult
			fmt.Fprint(w, `{"auth":{"client_token":"test","lease_duration":1}}`)
		case "/v1/secret/test":
			//noinspection GoUnhandledErrorResult
			fmt.Fprintf(w, `{"data":{"value":"%s"}}`, expected)
		}
	}))
	defer ts.Close()

	// Тестовый файл с токеном
	file, err := ioutil.TempFile("", "secenv-testing.*.tmp")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())

	// Записывает токен в тестовый файл
	_, err = file.WriteString("JWT")
	if err != nil {
		t.Error(err)
	}

	env := NewSecEnv(&Config{
		addr: ts.URL,
		auth: &Auth{
			mu:        &sync.Mutex{},
			method:    authKubernetes,
			tokenPath: file.Name(),
			expireAt:  time.Now(),
		},
	})

	err = os.Setenv(secEnvName, secEnvValue)
	value, err := env.Get(secEnvName)

	if err != nil {
		t.Error(err)
	}

	if value != expected {
		t.Errorf("expected \"%s\", got %s", expected, value)
	}
}
