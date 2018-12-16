package secenv

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

var (
	expected = "Ololo"
)

// Read environment variable without request to vault.
func TestSecEnv_Get(t *testing.T) {
	env := NewSecEnv(nil)

	err := os.Setenv("SECENV_TEST", expected)
	if err != nil {
		t.Error(err)
	}

	value, err := env.Get("SECENV_TEST")
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

	err := os.Setenv("SECENV_TEST", prefix+"test")
	value, err := env.Get("SECENV_TEST")
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

	err := os.Setenv("SECENV_TEST", prefix+"test.field")
	value, err := env.Get("SECENV_TEST")
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

	err := os.Setenv("SECENV_TEST", prefix+"test")
	if err != nil {
		t.Error(err)
	}

	_, err = env.Get("SECENV_TEST")
	if err == nil {
		t.Error("expected secenv error, got <nil>")
	}

	switch err.(type) {
	case *Error:
		if err.(*Error).msg != "no token provided" {
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

	err := os.Setenv("SECENV_TEST", prefix+"test")
	if err != nil {
		t.Error(err)
	}

	_, err = env.Get("SECENV_TEST")
	if err == nil {
		t.Error("expected url error, got <nil>")
	}

	switch err.(type) {
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

	err := os.Setenv("SECENV_TEST", prefix+"test")
	_, err = env.Get("SECENV_TEST")

	if err == nil {
		t.Error("expected json syntax error, got <nil>")
	}

	switch err.(type) {
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

	err := os.Setenv("SECENV_TEST", prefix+"test")
	_, err = env.Get("SECENV_TEST")

	if err == nil {
		t.Error("expected secenv error, got <nil>")
	}

	switch err.(type) {
	case *Error:
		if err.(*Error).msg != "no data returned" {
			t.Errorf("expected secenv error, got error %#v", err)
		}
	default:
		t.Errorf("expected secenv error, got error %#v", err)
	}
}
