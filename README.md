# Gator-Homes

A web application for property listings and rental management built with Go and MongoDB.

## Overview

Gator-Homes is a RESTful API that provides a platform for managing property listings. Features include:

- User authentication with JWT tokens
- Role-based authorization (admin and user roles)
- CORS policy implementation for frontend integration
- MongoDB integration for data persistence

## Project Structure

```
├── config/         # Configuration helpers
├── controllers/    # HTTP request handlers
├── middlewares/    # Middleware for auth, logging, CORS
├── models/         # Data models
├── routes/         # API route definitions
├── services/       # Business logic services
├── utils/          # Utility functions
├── go.mod          # Go module definition
├── go.sum          # Go dependencies checksum
└── main.go         # Application entry point
```

## Prerequisites

- Go 1.16+
- MongoDB 4.4+
- Git

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/abhiram-art/Gator-Homes.git
cd Gator-Homes
```

2. **Install Go dependencies**

```bash
go mod download
```

3. **Configure MongoDB**

Ensure MongoDB is running on your local machine or configure a connection to your MongoDB instance.

## Running the Application

Start the server with:

```bash
go run main.go
```

## Creating an Admin User

To create an admin user, use MongoDB Compass or a similar tool to add a user with the role field set to "admin":

1. Connect to your MongoDB database
2. Navigate to the "users" collection
3. Create a new document with:
   - firstName: "Admin"
   - lastName: "User"
   - email: "admin@example.com"
   - password: (bcrypt hashed password)
   - role: "admin"

## Authentication Flow

1. User registers or logs in and receives a JWT token
2. Token is sent with subsequent requests in the Authorization header
3. Token contains user role information for authorization
4. Protected routes verify the token and role before granting access

## Deployment

This application can be deployed to any platform that supports Go applications, such as:

- Docker containers
- Heroku
- Google Cloud Run
- AWS Elastic Beanstalk
