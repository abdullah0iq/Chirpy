package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	// Check if it starts with "Bearer "
	if !strings.HasPrefix(authHeader, "ApiKey ") {
		return "", errors.New("authorization header format must be 'Bearer TOKEN_STRING'")
	}
	// Strip off the "Bearer " prefix and return the token
	apiKey := strings.TrimSpace(authHeader[len("ApiKey "):])
	if apiKey == "" {
		return "", errors.New("token is missing")
	}
	return apiKey , nil 
}

// return token, nil
