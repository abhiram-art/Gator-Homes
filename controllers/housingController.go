package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/abhiram-art/Gator-Homes/middlewares"
	"github.com/abhiram-art/Gator-Homes/models"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// HousingController handles HTTP requests related to housing properties
type HousingController struct {
	collection *mongo.Collection
}

// NewHousingController creates a new housing controller
func NewHousingController(collection *mongo.Collection) *HousingController {
	return &HousingController{
		collection: collection,
	}
}

// CreateHousing creates a new housing property (admin only)
func (c *HousingController) CreateHousing(w http.ResponseWriter, r *http.Request) {
	// Verify admin role
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok || user.Role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	var housing models.Housing

	// Parse request body
	err := json.NewDecoder(r.Body).Decode(&housing)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Set metadata
	now := primitive.NewDateTimeFromTime(time.Now())
	housing.ID = primitive.NewObjectID()
	housing.CreatedAt = now
	housing.UpdatedAt = now

	// Insert into database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = c.collection.InsertOne(ctx, housing)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(housing)
}

// GetAllHousing retrieves all housing properties
func (c *HousingController) GetAllHousing(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set up options for sorting by most recent
	opts := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := c.collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer cursor.Close(ctx)

	var houses []models.Housing
	if err = cursor.All(ctx, &houses); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(houses)
}

// GetHousingByID retrieves a housing property by ID
func (c *HousingController) GetHousingByID(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid housing ID"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var housing models.Housing
	err = c.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&housing)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err == mongo.ErrNoDocuments {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Housing not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(housing)
}

// UpdateHousing updates a housing property (admin only)
func (c *HousingController) UpdateHousing(w http.ResponseWriter, r *http.Request) {
	// Verify admin role
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok || user.Role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid housing ID"})
		return
	}

	var housing models.Housing
	err = json.NewDecoder(r.Body).Decode(&housing)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Update metadata
	housing.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"type":      housing.Type,
			"name":      housing.Name,
			"image":     housing.Image,
			"country":   housing.Country,
			"address":   housing.Address,
			"bedrooms":  housing.Bedrooms,
			"bathrooms": housing.Bathrooms,
			"surface":   housing.Surface,
			"year":      housing.Year,
			"price":     housing.Price,
			"latitude":  housing.Latitude,
			"longitude": housing.Longitude,
			"agent":     housing.Agent,
			"updatedAt": housing.UpdatedAt,
		},
	}

	_, err = c.collection.UpdateOne(ctx, bson.M{"_id": id}, update)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Return updated housing
	housing.ID = id
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(housing)
}

// DeleteHousing deletes a housing property (admin only)
func (c *HousingController) DeleteHousing(w http.ResponseWriter, r *http.Request) {
	// Verify admin role
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok || user.Role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid housing ID"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := c.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if result.DeletedCount == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Housing not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Housing deleted successfully"})
}
