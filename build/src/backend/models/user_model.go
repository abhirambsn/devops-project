package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Id				primitive.ObjectID		`json:"_id,omitempty"`
	Username		string					`json:"username,omitempty" validate:"required"`
	Password		string					`json:"password,omitempty" validate:"required"`
	FullName		string					`json:"fullname,omitempty" validate:"required"`
}