package main

type ValidResponse struct {
	CleanedBody string `json:"cleaned_body"`
}
type ErrorResponse struct {
	Error string `json:"error"`
}
