package controllers

import (
	// "context"
	"encoding/json"
	// "log"
	"net/http"
	"os"

	// "time"

	"github.com/abhiram-art/Gator-Homes/middlewares"
	"github.com/abhiram-art/Gator-Homes/models"
	"github.com/abhiram-art/Gator-Homes/services"

	// "github.com/gorilla/mux"
	// "go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserController handles HTTP requests related to users
type UserController struct {
	collection  *mongo.Collection
	userService *services.UserService
}

// LoginRequest for user login data
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// RegisterRequest for user registration data
type RegisterRequest struct {
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Phone     string `json:"phone"`
	Password  string `json:"password" validate:"required,min=6"`
}

// NewUserController creates a new user controller
func NewUserController(collection *mongo.Collection) *UserController {
	return &UserController{
		collection:  collection,
		userService: services.NewUserService(collection),
	}
}

// setCookie sets a secure HTTP-only auth cookie
func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	isProduction := os.Getenv("GO_ENV") == "production"

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteNoneMode, // Adjust based on your CORS needs
		MaxAge:   maxAge,
		Path:     "/",
	})
}

// GetAuthStatus checks if user is authenticated
func (c *UserController) GetAuthStatus(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by auth middleware)
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Prepare response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isAuthenticated": true,
		"user": map[string]interface{}{
			"id":        user.ID.Hex(),
			"firstName": user.FirstName,
			"lastName":  user.LastName,
			"email":     user.Email,
			"role":      user.Role,
		},
	})
}

// LoginUser handles user login
func (c *UserController) LoginUser(w http.ResponseWriter, r *http.Request) {
	var loginRequest LoginRequest

	// Parse request body
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Authenticate user
	authResponse, err := c.userService.AuthenticateUser(loginRequest.Email, loginRequest.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Set auth cookie with the token
	setCookie(w, "authToken", authResponse.Token, 24*60*60) // 24 hours

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User logged in successfully",
		"user": map[string]interface{}{
			"id":        authResponse.User.ID,
			"firstName": authResponse.User.FirstName,
			"lastName":  authResponse.User.LastName,
			"email":     authResponse.User.Email,
			"role":      authResponse.User.Role,
			"token":     authResponse.Token,
		},
	})
}

// LogoutUser handles user logout
func (c *UserController) LogoutUser(w http.ResponseWriter, r *http.Request) {
	// Clear the cookie by setting an expired cookie
	setCookie(w, "authToken", "", -1)

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"})
}

// RegisterUser handles user registration
func (c *UserController) RegisterUser(w http.ResponseWriter, r *http.Request) {
	var registerRequest RegisterRequest

	// Parse request body
	err := json.NewDecoder(r.Body).Decode(&registerRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Create user model from request
	user := models.Users{
		FirstName: registerRequest.FirstName,
		LastName:  registerRequest.LastName,
		Email:     registerRequest.Email,
		Phone:     registerRequest.Phone,
		Password:  registerRequest.Password,
		Role:      "user", // Default role is user
	}

	// Create user
	authResponse, err := c.userService.CreateUser(user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Set auth cookie with the token
	setCookie(w, "authToken", authResponse.Token, 24*60*60) // 24 hours

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user": map[string]interface{}{
			"id":        authResponse.User.ID,
			"firstName": authResponse.User.FirstName,
			"lastName":  authResponse.User.LastName,
			"email":     authResponse.User.Email,
			"role":      authResponse.User.Role,
		},
	})
}

// GetMyProfile gets the authenticated user's profile
func (c *UserController) GetMyProfile(w http.ResponseWriter, r *http.Request) {
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": map[string]interface{}{
			"id":        user.ID.Hex(),
			"firstName": user.FirstName,
			"lastName":  user.LastName,
			"email":     user.Email,
			"phone":     user.Phone,
			"role":      user.Role,
		},
	})
}

// // SaveUserProfile saves or updates a user profile
// func (c *UserController) SaveUserProfile(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Save profile endpoint"})
// }

// // UpdateUser updates a user's profile
// func (c *UserController) UpdateUser(w http.ResponseWriter, r *http.Request) {
// 	// Get user from context - we need the user ID for the update
// 	user, ok := middlewares.GetUserFromContext(r.Context())
// 	if !ok {
// 		http.Error(w, "Unauthorized", http.StatusUnauthorized)
// 		return
// 	}

// 	var updateData map[string]interface{}

// 	// Parse request body
// 	err := json.NewDecoder(r.Body).Decode(&updateData)
// 	if err != nil {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
// 		return
// 	}

// 	// Build the update document
// 	update := bson.M{"$set": bson.M{}}

// 	// Add the fields that are provided in the request
// 	if firstName, ok := updateData["firstName"].(string); ok {
// 		update["$set"].(bson.M)["firstName"] = firstName
// 	}
// 	if lastName, ok := updateData["lastName"].(string); ok {
// 		update["$set"].(bson.M)["lastName"] = lastName
// 	}
// 	if phone, ok := updateData["phone"].(string); ok {
// 		update["$set"].(bson.M)["phone"] = phone
// 	}
// 	if country, ok := updateData["country"].(string); ok {
// 		update["$set"].(bson.M)["country"] = country
// 	}

// 	// Only update if there's at least one field to update
// 	if len(update["$set"].(bson.M)) > 0 {
// 		// Update the user in the database
// 		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 		defer cancel()

// 		_, err = c.collection.UpdateOne(
// 			ctx,
// 			bson.M{"_id": user.ID},
// 			update,
// 		)

// 		if err != nil {
// 			log.Println("Error updating user:", err)
// 			w.Header().Set("Content-Type", "application/json")
// 			w.WriteHeader(http.StatusInternalServerError)
// 			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update user profile"})
// 			return
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "User profile updated successfully"})
// }

// // GetUserProfile gets another user's profile
// func (c *UserController) GetUserProfile(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	userId := vars["userId"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"userId": userId, "message": "Get user profile endpoint"})
// }

// // SendEmailVerification sends verification email
// func (c *UserController) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Send email verification endpoint"})
// }

// // VerifyEmailAndRegister verifies email and registers user
// func (c *UserController) VerifyEmailAndRegister(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Verify email and register endpoint"})
// }

// // ResendVerification resends verification code
// func (c *UserController) ResendVerification(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Resend verification endpoint"})
// }

// // ForgotPassword initiates password reset
// func (c *UserController) ForgotPassword(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Forgot password endpoint"})
// }

// // VerifyResetCode verifies password reset code
// func (c *UserController) VerifyResetCode(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Verify reset code endpoint"})
// }

// // ResetPassword resets user password
// func (c *UserController) ResetPassword(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Reset password endpoint"})
// }

// // ChangeOldPassword changes user password
// func (c *UserController) ChangeOldPassword(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Change old password endpoint"})
// }
