package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// Create claims
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",                                            // Issuer of the token
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),                // Current time in UTC
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)), // Expiry time
		Subject:   userID.String(),                                     // User ID as a string
	}

	// Create the token with signing method and claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token using the secret key
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	// Return the signed token
	return signedToken, nil
}

// Set the Issuer to "chirpy"
// Set IssuedAt to the current time in UTC
// Set ExpiresAt to the current time plus the expiration time (expiresIn)
// Set the Subject to a stringified version of the user's id
// Use token.SignedString to sign the token with the secret key.
// Refer to here for an overview of the different signing methods and their respective key types.

// ValidateJWT validates a JWT token and extracts the user's UUID from the claims.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Parse the token and validate its signature and claims
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		// Provide the secret key for validation
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, errors.New("unauthorized: invalid or expired token")
	}

	// Extract claims from the token
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return uuid.Nil, errors.New("unauthorized: invalid token claims")
	}

	// Parse the Subject (user ID) as UUID
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, errors.New("unauthorized: invalid user ID in token")
	}

	// Return the user ID
	return userID, nil
}

// GetBearerToken extracts the token from the Authorization header.
func GetBearerToken(headers http.Header) (string, error) {
	// Get the Authorization header
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	// Check if it starts with "Bearer "
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", errors.New("authorization header format must be 'Bearer TOKEN_STRING'")
	}

	// Strip off the "Bearer " prefix and return the token
	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return "", errors.New("token is missing")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	randomBytes :=make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	token := hex.EncodeToString(randomBytes)
	return token , nil
}

// Add a func MakeRefreshToken() (string, error) function to your internal/auth package.
//  It should use the following to generate a random 256-bit (32-byte) hex-encoded string:
// rand.Read to generate 32 bytes (256 bits) of random data from the crypto/rand package (math/rand's Read function is deprecated).
// hex.EncodeToString to convert the random data to a hex string
