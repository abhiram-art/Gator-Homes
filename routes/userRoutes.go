package routes

import (
	"net/http"

	"github.com/abhiram-art/Gator-Homes/controllers"
	"github.com/abhiram-art/Gator-Homes/middlewares"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
)

// AdminMiddleware checks if the user has admin role
func AdminMiddleware(userCollection *mongo.Collection) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First apply auth middleware to get the user
			authMiddleware := middlewares.AuthMiddleware(userCollection)

			// Create a handler that checks the user role
			roleCheckHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, ok := middlewares.GetUserFromContext(r.Context())
				if !ok || user.Role != "admin" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"error":"Admin access required"}`))
					return
				}

				// If user is admin, proceed to next handler
				next.ServeHTTP(w, r)
			})

			// Apply auth middleware followed by role check
			authMiddleware(roleCheckHandler).ServeHTTP(w, r)
		})
	}
}

// SetupUserRoutes initializes all user-related routes
func SetupUserRoutes(router *mux.Router, db *mongo.Database) {
	// Initialize controllers
	userCollection := db.Collection("users")
	userController := controllers.NewUserController(userCollection)

	// Create auth middleware with the user collection
	authMiddleware := middlewares.AuthMiddleware(userCollection)

	// Create admin middleware (combines auth check and role check)
	adminMiddleware := AdminMiddleware(userCollection)

	// Public routes - no authentication required
	router.HandleFunc("/login", userController.LoginUser).Methods("POST")
	router.HandleFunc("/register", userController.RegisterUser).Methods("POST")
	router.HandleFunc("/logout", userController.LogoutUser).Methods("POST")

	// Protected routes - require authentication
	router.Handle("/auth/status", authMiddleware(http.HandlerFunc(userController.GetAuthStatus))).Methods("GET")
	router.Handle("/profile", authMiddleware(http.HandlerFunc(userController.GetMyProfile))).Methods("GET")

	// Admin routes - require admin role
	adminRouter := router.PathPrefix("/admin").Subrouter()
	adminRouter.Use(adminMiddleware)

	// Admin-specific routes will go here when needed
}
