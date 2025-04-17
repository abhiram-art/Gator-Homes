package utils

import (
	"time"
	"github.com/abhiram-art/Gator-Homes/config"
	"github.com/dgrijalva/jwt-go"
)

func GenerateToken(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(config.JwtSecretKey()))
}

func ValidateToken(token string) (*jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JwtSecretKey()), nil
	})
	if err != nil {
		return nil, err
	}
	return &claims, nil
}
