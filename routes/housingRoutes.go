package routes

import (
	"net/http"

	"github.com/abhiram-art/Gator-Homes/controllers"
	"github.com/abhiram-art/Gator-Homes/middlewares"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
)

// SetupHousingRoutes initializes all housing-related routes
func SetupHousingRoutes(router *mux.Router, db *mongo.Database) {
	// Initialize collections
	housingCollection := db.Collection("housing")

	// Initialize controllers
	housingController := controllers.NewHousingController(housingCollection)

	// Create auth middleware with the user collection
	userCollection := db.Collection("users")
	authMiddleware := middlewares.AuthMiddleware(userCollection)

	// Public routes - no authentication required
	router.HandleFunc("/all", housingController.GetAllHousing).Methods("GET")
	router.HandleFunc("/{id}", housingController.GetHousingByID).Methods("GET")

	// Protected routes for authenticated users
	router.Handle("/create", authMiddleware(http.HandlerFunc(housingController.CreateHousing))).Methods("POST")
	router.Handle("/{id}", authMiddleware(http.HandlerFunc(housingController.UpdateHousing))).Methods("PUT")
	router.Handle("/{id}", authMiddleware(http.HandlerFunc(housingController.DeleteHousing))).Methods("DELETE")
}
