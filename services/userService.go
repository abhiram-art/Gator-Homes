package services

import (
	"context"
	"errors"
	"time"

	"github.com/abhiram-art/Gator-Homes/models"
	"github.com/abhiram-art/Gator-Homes/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	collection *mongo.Collection
}

type UserResponse struct {
	ID         string `json:"id"`
	FirstName  string `json:"firstName"`
	LastName   string `json:"lastName"`
	Email      string `json:"email"`
	Role       string `json:"role"`
}

type AuthResponse struct {
	User  UserResponse `json:"user"`
	Token string       `json:"token"`
}

func NewUserService(collection *mongo.Collection) *UserService {
	return &UserService{
		collection: collection,
	}
}

func (s *UserService) AuthenticateUser(email, password string) (*AuthResponse, error) {
	var user models.Users
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := s.collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("invalid email or password")
		}
		return nil, err
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Generate token
	token, err := utils.GenerateToken(user.ID.Hex())
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User: UserResponse{
			ID:         user.ID.Hex(),
			FirstName:  user.FirstName,
			LastName:   user.LastName,
			Email:      user.Email,
			Role:       user.Role,
		},
		Token: token,
	}, nil
}

func (s *UserService) CreateUser(userData models.Users) (*AuthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if user with same email already exists
	existingUser := s.collection.FindOne(ctx, bson.M{"email": userData.Email})
	if existingUser.Err() == nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	userData.Password = string(hashedPassword)

	// Set ID
	userData.ID = primitive.NewObjectID()
	
	// Set default role to "user" if not specified
	if userData.Role == "" {
		userData.Role = "user"
	}

	// Insert user into database
	_, err = s.collection.InsertOne(ctx, userData)
	if err != nil {
		return nil, err
	}

	// Generate token
	token, err := utils.GenerateToken(userData.ID.Hex())
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User: UserResponse{
			ID:         userData.ID.Hex(),
			FirstName:  userData.FirstName,
			LastName:   userData.LastName,
			Email:      userData.Email,
			Role:       userData.Role,
		},
		Token: token,
	}, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(userID string) (*models.Users, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, err
	}

	var user models.Users
	err = s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
