package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abhiram-art/Gator-Homes/config"
	"github.com/abhiram-art/Gator-Homes/routes"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found or error loading .env file")
	}

	// Connect to MongoDB
	log.Println("Connecting to MongoDB...")
	mongoURI := config.EnvMongoURI()
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error creating MongoDB client:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Fatal("Error disconnecting from MongoDB:", err)
		}
	}()

	log.Println("Connected to MongoDB successfully")

	// Set up database
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "Gator-Homes"
	}
	db := client.Database(dbName)
	log.Printf("Using database: %s", dbName)

	// Create router
	r := mux.NewRouter()

	// Apply global middleware
	r.Use(corsMiddleware)
	r.Use(loggingMiddleware)

	// Setup API routes
	apiRouter := r.PathPrefix("/api").Subrouter()

	// Setup user routes
	routes.SetupUserRoutes(apiRouter.PathPrefix("/users").Subrouter(), db)

	// Setup housing routes
	routes.SetupHousingRoutes(apiRouter.PathPrefix("/housing").Subrouter(), db)

	// Setup property request routes
	routes.SetupRequestRoutes(apiRouter.PathPrefix("/requests").Subrouter(), db)

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	log.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// corsMiddleware adds CORS headers to responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get allowed origins from environment
		allowedOrigins := getAllowedOrigins()

		// Get the origin of the request
		origin := r.Header.Get("Origin")

		if isAllowedOrigin(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			if len(allowedOrigins) > 0 {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigins[0])
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		}

		// Set other CORS headers
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getAllowedOrigins gets the allowed origins from environment
func getAllowedOrigins() []string {
	// Get allowed origins from environment variable
	allowedOriginsEnv := os.Getenv("ALLOWED_ORIGINS")
	if allowedOriginsEnv == "" {
		// Default allowed origins if not specified
		return []string{
			"http://localhost:3000",       // Local development frontend React
			"http://localhost:4200",       // Angular local development
			"https://www.gator-homes.com", // Production
		}
	}

	// Split the comma-separated list of allowed origins
	return strings.Split(allowedOriginsEnv, ",")
}

// isAllowedOrigin checks if an origin is in the list of allowed origins
func isAllowedOrigin(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range allowedOrigins {
		if origin == strings.TrimSpace(allowed) {
			return true
		}
	}

	return false
}

// loggingMiddleware logs all requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}
