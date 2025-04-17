package middlewares

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/abhiram-art/Gator-Homes/models"
	"github.com/abhiram-art/Gator-Homes/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Define a custom type for context keys
type contextKey string

// ContextUserKey is the key used for storing user in context
const ContextUserKey contextKey = "user"

// AuthMiddleware verifies the token and attaches the user to the request context
func AuthMiddleware(userCollection *mongo.Collection) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header or cookie
			tokenHeader := r.Header.Get("Authorization")
			var token string
			
			// Extract token from Authorization header (remove Bearer prefix if present)
			if tokenHeader != "" {
				// Check if the header has the Bearer prefix
				if strings.HasPrefix(tokenHeader, "Bearer ") {
					token = strings.TrimPrefix(tokenHeader, "Bearer ")
				} else {
					// If no Bearer prefix, use as is
					token = tokenHeader
				}
			}
			
			// If no token in header, check cookies
			if token == "" {
				cookie, err := r.Cookie("authToken")
				if err == nil {
					token = cookie.Value
				}
			}
			
			// If still no token, return unauthorized
			if token == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"isAuthenticated": false,
					"message": "No token provided",
				})
				return
			}
			
			// Validate token
			claims, err := utils.ValidateToken(token)
			if err != nil {
				log.Println("Invalid token:", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"isAuthenticated": false,
					"message": "Invalid token",
				})
				return
			}
			
			// Extract user ID from claims
			userIDStr, ok := (*claims)["userID"].(string)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"isAuthenticated": false,
					"message": "Invalid token format",
				})
				return
			}
			
			// Convert string ID to ObjectID
			userID, err := primitive.ObjectIDFromHex(userIDStr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"isAuthenticated": false,
					"message": "Invalid user ID",
				})
				return
			}
			
			// Find user in database
			var user models.Users
			err = userCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
			if err != nil {
				log.Println("User not found:", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"isAuthenticated": false,
					"message": "User not found",
				})
				return
			}
			
			// Add user to context
			ctx := context.WithValue(r.Context(), ContextUserKey, user)
			
			// Proceed to next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromContext extracts the user from the request context
func GetUserFromContext(ctx context.Context) (models.Users, bool) {
	user, ok := ctx.Value(ContextUserKey).(models.Users)
	return user, ok
}





