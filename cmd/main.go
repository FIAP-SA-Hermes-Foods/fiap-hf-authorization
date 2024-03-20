package main

import (
	"fiap-hf-authorization/external/jwt"
	"fiap-hf-authorization/internal/handler/web"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/marcos-dev88/genv"
)

func init() {
	if err := genv.New(); err != nil {
		log.Printf("error to define envs: %v", err)
	}
}

func main() {

	jwtCall := jwt.New(
		os.Getenv("JWT_ISSUER"),
		os.Getenv("JWT_USERNAME"),
		time.Hour,
	)

	handler := web.NewHandler(jwtCall)
	lambda.Start(handler.Authorization)
}
