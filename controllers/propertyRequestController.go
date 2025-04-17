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

// PropertyRequestController handles HTTP requests related to property requests
type PropertyRequestController struct {
	collection  *mongo.Collection
	housingColl *mongo.Collection
}

// CreateRequestBody represents the request body for creating a property request
type CreateRequestBody struct {
	PropertyID string `json:"propertyId" validate:"required"`
	Message    string `json:"message"`
}

// UpdateRequestBody represents the request body for updating a property request status
type UpdateRequestBody struct {
	Status string `json:"status" validate:"required,oneof=pending approved rejected"`
}

// NewPropertyRequestController creates a new property request controller
func NewPropertyRequestController(collection *mongo.Collection, housingColl *mongo.Collection) *PropertyRequestController {
	return &PropertyRequestController{
		collection:  collection,
		housingColl: housingColl,
	}
}

// CreateRequest creates a new property request
func (c *PropertyRequestController) CreateRequest(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Admin cannot create property requests
	if user.Role == "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admins cannot create property requests"})
		return
	}

	var requestBody CreateRequestBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate property ID
	propertyID, err := primitive.ObjectIDFromHex(requestBody.PropertyID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid property ID"})
		return
	}

	// Check if property exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var housing models.Housing
	err = c.housingColl.FindOne(ctx, bson.M{"_id": propertyID}).Decode(&housing)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err == mongo.ErrNoDocuments {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Property not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
		return
	}

	// Check if user already has a pending request for this property
	var existingRequest models.PropertyRequest
	err = c.collection.FindOne(ctx, bson.M{
		"userId":     user.ID,
		"propertyId": propertyID,
		"status":     models.StatusPending,
	}).Decode(&existingRequest)

	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "You already have a pending request for this property"})
		return
	} else if err != mongo.ErrNoDocuments {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Create new request
	now := primitive.NewDateTimeFromTime(time.Now())
	propertyRequest := models.PropertyRequest{
		ID:         primitive.NewObjectID(),
		UserID:     user.ID,
		PropertyID: propertyID,
		Status:     models.StatusPending,
		Message:    requestBody.Message,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	_, err = c.collection.InsertOne(ctx, propertyRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(propertyRequest)
}

// GetMyRequests retrieves all requests for the authenticated user
func (c *PropertyRequestController) GetMyRequests(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Regular users can only see their own requests
	if user.Role != "admin" {
		c.getUserRequests(w, r, user.ID)
		return
	}

	// Admin can see all requests
	c.getAllRequests(w, r)
}

// getUserRequests gets requests for a specific user
func (c *PropertyRequestController) getUserRequests(w http.ResponseWriter, r *http.Request, userID primitive.ObjectID) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set up options for sorting by most recent
	opts := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := c.collection.Find(ctx, bson.M{"userId": userID}, opts)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer cursor.Close(ctx)

	var requests []models.PropertyRequest
	if err = cursor.All(ctx, &requests); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Enrich requests with property data
	enrichedRequests, err := c.enrichRequests(ctx, requests)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrichedRequests)
}

// getAllRequests gets all requests (admin only)
func (c *PropertyRequestController) getAllRequests(w http.ResponseWriter, r *http.Request) {
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

	var requests []models.PropertyRequest
	if err = cursor.All(ctx, &requests); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Enrich requests with property data
	enrichedRequests, err := c.enrichRequests(ctx, requests)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrichedRequests)
}

// EnrichedPropertyRequest includes property details with request
type EnrichedPropertyRequest struct {
	models.PropertyRequest
	Property models.Housing `json:"property"`
}

// enrichRequests adds property data to requests
func (c *PropertyRequestController) enrichRequests(ctx context.Context, requests []models.PropertyRequest) ([]EnrichedPropertyRequest, error) {
	var enriched []EnrichedPropertyRequest

	for _, req := range requests {
		var housing models.Housing
		err := c.housingColl.FindOne(ctx, bson.M{"_id": req.PropertyID}).Decode(&housing)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// If property not found, use an empty housing object
				housing = models.Housing{
					Name: "Property not found",
				}
			} else {
				return nil, err
			}
		}

		enriched = append(enriched, EnrichedPropertyRequest{
			PropertyRequest: req,
			Property:        housing,
		})
	}

	return enriched, nil
}

// UpdateRequestStatus updates the status of a property request (admin only)
func (c *PropertyRequestController) UpdateRequestStatus(w http.ResponseWriter, r *http.Request) {
	// Verify admin role
	user, ok := middlewares.GetUserFromContext(r.Context())
	if !ok || user.Role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	// Get request ID from URL
	params := mux.Vars(r)
	requestID, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request ID"})
		return
	}

	// Parse request body
	var updateBody UpdateRequestBody
	err = json.NewDecoder(r.Body).Decode(&updateBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate status
	if updateBody.Status != models.StatusPending &&
		updateBody.Status != models.StatusApproved &&
		updateBody.Status != models.StatusRejected {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid status value"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Update status
	now := primitive.NewDateTimeFromTime(time.Now())
	update := bson.M{
		"$set": bson.M{
			"status":    updateBody.Status,
			"updatedAt": now,
		},
	}

	result, err := c.collection.UpdateOne(ctx, bson.M{"_id": requestID}, update)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if result.ModifiedCount == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Request not found"})
		return
	}

	// Get updated request
	var request models.PropertyRequest
	err = c.collection.FindOne(ctx, bson.M{"_id": requestID}).Decode(&request)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(request)
}
