package main

import (
	"sync/atomic"

	"github.com/abdullah0iq/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkaApiKey    string
}

//The atomic.Int32 type is a really cool standard-library type that allows us to
//safely increment and read an integer value across multiple goroutines (HTTP requests).
