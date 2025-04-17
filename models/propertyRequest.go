package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Request status constants
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

// PropertyRequest represents a user's request for a property
type PropertyRequest struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID     primitive.ObjectID `bson:"userId" json:"userId"`
	PropertyID primitive.ObjectID `bson:"propertyId" json:"propertyId"`
	Status     string             `bson:"status" json:"status" default:"pending"`
	Message    string             `bson:"message" json:"message,omitempty"`
	CreatedAt  primitive.DateTime `bson:"createdAt" json:"createdAt"`
	UpdatedAt  primitive.DateTime `bson:"updatedAt" json:"updatedAt"`
}
