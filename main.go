package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/abdullah0iq/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func init() {
	// Set global log flags once
	log.SetFlags(log.Lshortfile) // Excludes date/time, includes file and line number
	log.SetOutput(os.Stdout)     // Optionally set the log output to standard output
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polkaApiKey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Print("god help us the database is not connected")
	}
	dbQueries := database.New(db)
	apiCfg := &apiConfig{db: dbQueries, platform: platform, secret: secret, polkaApiKey: polkaApiKey}
	apiCfg.fileserverHits.Store(0)

	mux := http.NewServeMux()

	registerHandlers(mux, apiCfg)

	// Start the server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	srv.ListenAndServe()
}

func registerHandlers(mux *http.ServeMux, apiCfg *apiConfig) {
	// Fileserver with metrics middleware
	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileServer)))

	// Static assets
	fsAssets := http.StripPrefix("/app/assets", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir("./assets"))))
	mux.Handle("/app/assets/", fsAssets)

	// Readiness endpoint
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	// Metrics endpoint
	mux.HandleFunc("GET /admin/metrics", apiCfg.hitHandler)

	// Reset endpoint
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	mux.HandleFunc("POST /api/chirps", apiCfg.postChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsHandler)
	mux.HandleFunc("GET /api/chirps/", apiCfg.getChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/", apiCfg.deleteChirpHandler)

	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshTokenHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeUserHandler)
}
