package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/abdullah0iq/chirpy/internal/auth"
	"github.com/abdullah0iq/chirpy/internal/database"
	"github.com/google/uuid"
)

func readinessHandler(resWriter http.ResponseWriter, req *http.Request) {
	resWriter.Header().Add("Content-Type", "text/plain; charset=utf-8")
	resWriter.WriteHeader(200)
	resWriter.Write([]byte("OK"))

}
func (cfg *apiConfig) hitHandler(resWriter http.ResponseWriter, req *http.Request) {
	resWriter.Header().Add("Content-Type", "text/plain; charset=utf-8")
	resWriter.WriteHeader(200)
	resWriter.Write([]byte(fmt.Sprintf(`
		<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}
func (cfg *apiConfig) resetHandler(resWriter http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		resWriter.WriteHeader(403)
		return
	}
	cfg.db.DeleteAllUsers(context.Background())
}

func (cfg *apiConfig) postChirpHandler(resWriter http.ResponseWriter, req *http.Request) {

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	id, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		sendErrorResponse(resWriter, 400, "Something went wrong")
		return
	}

	chirp := database.Chirp{}
	if err := json.Unmarshal(data, &chirp); err != nil {
		sendErrorResponse(resWriter, 400, "Invalid request format")
		return
	}

	if len(chirp.Body) > 140 {
		sendErrorResponse(resWriter, 400, "Chirp is too long")
		return
	}
	chirp, err = cfg.db.CreateChirp(context.Background(), database.CreateChirpParams{Body: chirp.Body, UserID: id})
	if err != nil {
		sendErrorResponse(resWriter, 500, "failed to create the chirp")
		return
	}
	data, err = json.Marshal(chirp)
	if err != nil {
		sendErrorResponse(resWriter, 400, "failed to parse the JSON")
		return
	}
	resWriter.WriteHeader(201)
	resWriter.Write(data)

}
func (cfg *apiConfig) getAllChirpsHandler(resWriter http.ResponseWriter, req *http.Request) {
	// Parse query parameters
	authorId := req.URL.Query().Get("author_id")
	sorted := req.URL.Query().Get("sort")

	// Default sort order to "asc" if not provided
	if sorted == "" {
		sorted = "asc"
	}

	// Validate sort order
	if sorted != "asc" && sorted != "desc" {
		log.Println("Invalid sort order:", sorted)
		resWriter.WriteHeader(http.StatusBadRequest)
		resWriter.Write([]byte(`{"error": "Invalid sort order. Use 'asc' or 'desc'."}`))
		return
	}

	var chirps []database.Chirp
	var err error

	if authorId != "" {
		// Parse and validate author_id
		uuidAuthorID, parseErr := uuid.Parse(authorId)
		if parseErr != nil {
			log.Printf("Failed to parse author_id: %v\n", parseErr)
			resWriter.WriteHeader(http.StatusBadRequest)
			resWriter.Write([]byte(`{"error": "Invalid author_id format."}`))
			return
		}
		// Fetch chirps by author ID
		if sorted == "asc" {
			chirps, err = cfg.db.GetAllChirpsByAuthorIdAsc(context.Background(), uuidAuthorID)
		} else {
			chirps, err = cfg.db.GetAllChirpsByAuthorIdDesc(context.Background(), uuidAuthorID)
		}

		if err != nil {
			log.Printf("Database error while fetching chirps by author_id (%s): %v\n", authorId, err)
			resWriter.WriteHeader(http.StatusInternalServerError)
			resWriter.Write([]byte(`{"error": "Failed to fetch chirps by author ID."}`))
			return
		}
	} else {
		// Fetch all chirps
		if sorted == "asc" {
			chirps, err = cfg.db.GetAllChirpsAsc(context.Background())
		} else {
			chirps, err = cfg.db.GetAllChirpsDesc(context.Background())
		}
		if err != nil {
			log.Printf("Database error while fetching all chirps: %v\n", err)
			resWriter.WriteHeader(http.StatusInternalServerError)
			resWriter.Write([]byte(`{"error": "Failed to fetch chirps."}`))
			return
		}

	}

	// Marshal chirps to JSON
	data, jsonErr := json.Marshal(chirps)
	if jsonErr != nil {
		log.Printf("Failed to marshal chirps to JSON: %v\n", jsonErr)
		resWriter.WriteHeader(http.StatusInternalServerError)
		resWriter.Write([]byte(`{"error": "Failed to process chirps data."}`))
		return
	}

	// Send success response
	resWriter.Header().Set("Content-Type", "application/json")
	resWriter.WriteHeader(http.StatusOK)
	resWriter.Write(data)
}
func (cfg *apiConfig) getChirpHandler(resWriter http.ResponseWriter, req *http.Request) {
	chirpIDStr := req.URL.Path[len("/api/chirps/"):]
	chirpId, err := uuid.Parse(chirpIDStr)
	if err != nil {
		resWriter.WriteHeader(400)
		return
	}
	chirp, err := cfg.db.GetChirp(context.Background(), chirpId)
	if err != nil {
		resWriter.WriteHeader(404)
		return
	}
	data, err := json.Marshal(chirp)
	if err != nil {
		resWriter.WriteHeader(500)
		return
	}
	resWriter.WriteHeader(200)
	resWriter.Write(data)

}
func (cfg *apiConfig) deleteChirpHandler(resWriter http.ResponseWriter, req *http.Request) {
	chirpIDStr := req.URL.Path[len("/api/chirps/"):]
	reqChirpId, err := uuid.Parse(chirpIDStr)
	if err != nil {
		log.Printf("couldn't parse the chirp id from the url: %v", err)
		resWriter.WriteHeader(400)
		return
	}
	chirp, err := cfg.db.GetChirp(context.Background(), reqChirpId)
	if err != nil {
		log.Printf("Couldnt not find the chirp. dbError: %v", err)
		resWriter.WriteHeader(404)
		return
	}
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Problem with Bearer Token: %v", err)
		resWriter.WriteHeader(401)
		return
	}
	tokenUserId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		log.Printf("Couldn't validate the token: %v", err)
		resWriter.WriteHeader(403)
		return
	}
	if tokenUserId != chirp.UserID {
		log.Println("couldn't delete the chirp. Not authorized.")
		resWriter.WriteHeader(403)
		return
	}
	if err = cfg.db.DeleteChirp(context.Background(), database.DeleteChirpParams{
		ID:     reqChirpId,
		UserID: tokenUserId,
	}); err != nil {
		log.Printf("couldn't delete the chirp. Not authorized. err: %v", err)
		resWriter.WriteHeader(403)
		return
	}
	resWriter.WriteHeader(204)
}

func sendErrorResponse(resWriter http.ResponseWriter, statusCode int, message string) {
	resWriter.WriteHeader(statusCode)
	resData, _ := json.Marshal(ErrorResponse{Error: message})
	if _, err := resWriter.Write(resData); err != nil {
		log.Printf("Failed to write error response: %v\n", err)
	}
}
func sendSuccessResponse(resWriter http.ResponseWriter, response interface{}) {
	resWriter.WriteHeader(200)
	resData, _ := json.Marshal(response)
	if _, err := resWriter.Write(resData); err != nil {
		log.Printf("Failed to write success response: %v\n", err)
	}
}

func checkProfaneWords(text string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	words := strings.Split(text, " ")

	for i, word := range words {
		for _, p := range profaneWords {
			if strings.ToLower(word) == p {
				words[i] = "****"
				break
			}
		}
	}
	return strings.Join(words, " ")

}

func (cfg *apiConfig) createUser(resWriter http.ResponseWriter, req *http.Request) {
	// Request structure

	// Read request body
	data, err := io.ReadAll(req.Body)
	if err != nil {
		sendErrorResponse(resWriter, 400, "failed to parse the data")
		return
	}

	// Parse request data
	newUser := database.User{}
	if err := json.Unmarshal(data, &newUser); err != nil {
		sendErrorResponse(resWriter, 400, "failed to parse the JSON")
		return
	}
	hash_password, err := auth.HashPassword(newUser.Password)
	if err != nil {
		resWriter.WriteHeader(500)
	}

	// Call database layer to create user
	user, err := cfg.db.CreateUser(context.Background(), database.CreateUserParams{Email: newUser.Email, Password: hash_password})
	if err != nil {
		sendErrorResponse(resWriter, 500, "failed to create the user")
		return
	}

	// Send success response
	resWriter.Header().Set("Content-Type", "application/json")
	resWriter.WriteHeader(201) // HTTP 201 Created
	data, err = json.Marshal(user)
	if err != nil {
		sendErrorResponse(resWriter, 500, "failed to create the user")
		return
	}
	resWriter.Write(data)
}

func (cfg *apiConfig) loginHandler(resWriter http.ResponseWriter, req *http.Request) {

	type LoginRequest struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type LoginResponse struct {
		ID           string    `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}

	//validate the request
	data, err := io.ReadAll(req.Body)
	if err != nil {
		resWriter.WriteHeader(400)
		return
	}
	loginRequest := LoginRequest{}
	if err = json.Unmarshal(data, &loginRequest); err != nil {
		resWriter.WriteHeader(500)
		return
	}
	user, err := cfg.db.GetUserByEmail(context.Background(), loginRequest.Email)
	if err != nil {
		resWriter.WriteHeader(401)
		resWriter.Write([]byte("Incorrect email or password"))
		return
	}
	if err = auth.CheckPasswordHash(loginRequest.Password, user.Password); err != nil {
		resWriter.WriteHeader(401)
		resWriter.Write([]byte("Incorrect email or password"))
		return
	}

	//Create Access Token
	accessToken, err := auth.MakeJWT(user.ID, cfg.secret, time.Hour)
	if err != nil {
		resWriter.WriteHeader(500)
		return
	}

	//Create Refresh Token
	refreshTokenString, err := auth.MakeRefreshToken()
	if err != nil {
		resWriter.WriteHeader(500)
		return
	}
	refreshToken, err := cfg.db.InsertRefreshToken(context.Background(), database.InsertRefreshTokenParams{Token: refreshTokenString, UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour * 24 * 60)})
	if err != nil {
		resWriter.WriteHeader(500)
		return
	}

	//Response with the data
	data, err = json.Marshal(LoginResponse{
		ID:           user.ID.String(),
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        accessToken,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	})
	if err != nil {
		resWriter.Write([]byte("failed to send user back at marshaling"))
		resWriter.WriteHeader(500)
		return

	}
	resWriter.WriteHeader(200)
	resWriter.Write(data)

}

func (cfg *apiConfig) refreshTokenHandler(resWriter http.ResponseWriter, req *http.Request) {

	//1.Validate request
	//	1.validate Header's Token
	if req.ContentLength > 0 {
		resWriter.WriteHeader(401)
		return
	}
	headerToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	refreshToken, err := cfg.db.GetRefreshToken(context.Background(), headerToken)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	// 	2.Check for Expire_at
	if !refreshToken.ExpiresAt.After(time.Now()) {
		resWriter.WriteHeader(401)
		return
	}
	// 3.check if revoked
	if refreshToken.RevokedAt.Valid {
		resWriter.WriteHeader(401)
		return
	}
	log.Println(refreshToken.ExpiresAt)

	//2.Create the response
	accessToken, err := auth.MakeJWT(refreshToken.UserID, cfg.secret, time.Hour)
	if err != nil {
		resWriter.WriteHeader(500)
		return

	}
	type Res struct {
		Token string `json:"token"`
	}
	data, err := json.Marshal(Res{Token: accessToken})
	if err != nil {
		resWriter.WriteHeader(500)
		return
	}
	resWriter.WriteHeader(200)
	resWriter.Write(data)

}

func (cfg *apiConfig) revokeRefreshTokenHandler(resWriter http.ResponseWriter, req *http.Request) {
	//1.Validate request
	//	1.validate Header's Token
	if req.ContentLength > 0 {
		resWriter.WriteHeader(401)
		return
	}
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	err = cfg.db.RevokeToken(context.Background(), refreshToken)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	resWriter.WriteHeader(204)
}

func (cfg *apiConfig) updateUserHandler(resWriter http.ResponseWriter, req *http.Request) {
	headerToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("couldn't get header token : %v", err)
		resWriter.WriteHeader(401)
		return
	}
	type Req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	reqBody := Req{}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("couldn't parse the data from the req body : %v", err)

		resWriter.WriteHeader(500)
		return
	}

	if err = json.Unmarshal(data, &reqBody); err != nil {
		log.Printf("couldn't unmarshal the data from the req body : %v", err)
		resWriter.WriteHeader(500)
		return
	}
	if reqBody.Email == "" || reqBody.Password == "" {
		log.Printf("email or password is empty string. email: %v, password:%v", reqBody.Email, reqBody.Password)
		resWriter.WriteHeader(400)
		return
	}

	id, err := auth.ValidateJWT(headerToken, cfg.secret)
	if err != nil {
		resWriter.WriteHeader(401)
		return
	}
	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		log.Printf("couldn't hash the password. the password:%v : %v", reqBody.Password, err)
		resWriter.WriteHeader(500)
		return
	}

	resBody, err := cfg.db.UpdateUser(context.Background(), database.UpdateUserParams{Password: hashedPassword, Email: reqBody.Email, ID: id})
	if err != nil {
		log.Printf("couldn't update the user : %v", err)
		resWriter.WriteHeader(500)
		return
	}
	data, err = json.Marshal(resBody)
	if err != nil {
		log.Printf("couldn't marshal the user to json : %v", err)
		resWriter.WriteHeader(500)
		return
	}
	resWriter.WriteHeader(200)
	resWriter.Write(data)
}

func (cfg *apiConfig) upgradeUserHandler(resWriter http.ResponseWriter, req *http.Request) {
	type ReqBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}
	reqApiKey, err := auth.GetAPIKey(req.Header)
	if err != nil || reqApiKey != cfg.polkaApiKey {
		log.Println(err)
		resWriter.WriteHeader(401)
		return
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		log.Print(err)
		resWriter.WriteHeader(500)
		return
	}
	reqBody := ReqBody{}
	if err = json.Unmarshal(data, &reqBody); err != nil {
		log.Print(err)
		resWriter.WriteHeader(500)
		return
	}
	user, err := cfg.db.GetUserById(context.Background(), reqBody.Data.UserID)
	if err != nil {
		log.Print(err)
		resWriter.WriteHeader(500)
		return
	}
	if user.ID != reqBody.Data.UserID {
		resWriter.WriteHeader(404)
		return
	}
	if reqBody.Event == "user.upgraded" {
		if err = cfg.db.UpgradeUser(context.Background(), reqBody.Data.UserID); err != nil {
			log.Print(err)
			resWriter.WriteHeader(500)
			return
		}
		log.Println("User upgraded successfully")
		resWriter.WriteHeader(204)
		return
	}
	log.Println("Event is not defined")
	resWriter.WriteHeader(204)
	return

}
