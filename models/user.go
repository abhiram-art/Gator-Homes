package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Users struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	FirstName string             `bson:"firstName" json:"firstName" validate:"required"`
	LastName  string             `bson:"lastName" json:"lastName" validate:"required"`
	Email     string             `bson:"email" json:"email" validate:"required,email"`
	Phone     string             `bson:"phone" json:"phone,omitempty"`
	Password  string             `bson:"password" json:"password,omitempty" validate:"required,min=6"`
	Role      string             `bson:"role" json:"role,omitempty" default:"user"` // Role can be "admin" or "user"
}
