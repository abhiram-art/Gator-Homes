package routes

import (
	"net/http"

	"github.com/abhiram-art/Gator-Homes/controllers"
	"github.com/abhiram-art/Gator-Homes/middlewares"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
)

// SetupRequestRoutes initializes all property request-related routes
func SetupRequestRoutes(router *mux.Router, db *mongo.Database) {
	// Initialize collections
	requestCollection := db.Collection("propertyRequests")
	housingCollection := db.Collection("housing")

	// Initialize controllers
	requestController := controllers.NewPropertyRequestController(requestCollection, housingCollection)

	// Create auth middleware with the user collection
	userCollection := db.Collection("users")
	authMiddleware := middlewares.AuthMiddleware(userCollection)

	// All request routes require authentication
	router.Handle("/create", authMiddleware(http.HandlerFunc(requestController.CreateRequest))).Methods("POST")
	router.Handle("/my-requests", authMiddleware(http.HandlerFunc(requestController.GetMyRequests))).Methods("GET")
	router.Handle("/{id}/status", authMiddleware(http.HandlerFunc(requestController.UpdateRequestStatus))).Methods("PUT")
}
