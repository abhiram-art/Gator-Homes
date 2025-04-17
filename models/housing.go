package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Agent represents a contact person for a property
type Agent struct {
	Name  string `bson:"name" json:"name"`
	Phone string `bson:"phone" json:"phone"`
}

// Housing represents a housing property
type Housing struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Type      string             `bson:"type" json:"type" validate:"required"`
	Name      string             `bson:"name" json:"name" validate:"required"`
	Image     string             `bson:"image" json:"image"`
	County    string             `bson:"county" json:"county"`
	Address   string             `bson:"address" json:"address" validate:"required"`
	Bedrooms  string             `bson:"bedrooms" json:"bedrooms"`
	Bathrooms string             `bson:"bathrooms" json:"bathrooms"`
	Surface   string             `bson:"surface" json:"surface"`
	Year      string             `bson:"year" json:"year"`
	Price     string             `bson:"price" json:"price" validate:"required"`
	Latitude  float64            `bson:"latitude" json:"latitude"`
	Longitude float64            `bson:"longitude" json:"longitude"`
	Agent     Agent              `bson:"agent" json:"agent"`
	CreatedAt primitive.DateTime `bson:"createdAt" json:"createdAt"`
	UpdatedAt primitive.DateTime `bson:"updatedAt" json:"updatedAt"`
}
