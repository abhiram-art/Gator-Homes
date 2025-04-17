package config

import "os"

// EnvMongoURI returns the MongoDB connection string from environment variables
func EnvMongoURI() string {
	uri := os.Getenv("MONGO_URI")
	return uri
}

// JwtSecretKey returns the JWT secret key from environment variables
func JwtSecretKey() string {
	return os.Getenv("JWT_SECRET")
}
