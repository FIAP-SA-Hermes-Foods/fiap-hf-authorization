package web

import (
	"context"
	"errors"
	"fiap-hf-authorization/external/jwt"
	"fmt"
	"os"

	awsEvents "github.com/aws/aws-lambda-go/events"
)

type HandlerAuth interface {
	Authorization(ctx context.Context, event awsEvents.APIGatewayV2CustomAuthorizerV2Request) (awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse, error)
}

type handlerAuth struct {
	jwtHf jwt.JwtHF
}

func NewHandler(jwtHf jwt.JwtHF) *handlerAuth {
	return &handlerAuth{jwtHf: jwtHf}
}

func (h *handlerAuth) Authorization(ctx context.Context, event awsEvents.APIGatewayV2CustomAuthorizerV2Request) (awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	var token string
	token, ok := event.Headers["authorization"]

	if !ok {
		return awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
			Context: map[string]interface{}{
				"status":  "Unauthorized",
				"headers": event.Headers,
			},
		}, errors.New(fmt.Sprintf("Unauthorized | %v", event.Headers))

	}

	statusCode, err := h.jwtHf.ValidateToken(token, []byte(os.Getenv("JWT_SIGIN_KEY")))

	if err != nil {
		return awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
			Context: map[string]interface{}{
				"status": "Unauthorized",
				"debug1": token,
			},
		}, fmt.Errorf("error: %v", err)
	}

	if statusCode != 200 {
		return awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
			Context: map[string]interface{}{
				"status": "Unauthorized",
				"debug2": token,
			},
		}, errors.New(fmt.Sprintf("Unauthorized | %v", event.Headers))

	}

	return awsEvents.APIGatewayV2CustomAuthorizerSimpleResponse{
		IsAuthorized: true,
		Context: map[string]interface{}{
			"status": "OK",
		},
	}, nil
}
