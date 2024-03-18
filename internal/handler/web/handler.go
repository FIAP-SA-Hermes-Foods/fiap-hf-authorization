package web

import (
	"context"
	"errors"
	"fiap-hf-authorization/external/jwt"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	awsEvents "github.com/aws/aws-lambda-go/events"
)

type HandlerAuth interface {
	Authorization(ctx context.Context, event awsEvents.APIGatewayCustomAuthorizerRequest) (awsEvents.APIGatewayCustomAuthorizerResponse, error)
}

type handlerAuth struct {
	jwtHf jwt.JwtHF
}

func NewHandler(jwtHf jwt.JwtHF) *handlerAuth {
	return &handlerAuth{jwtHf: jwtHf}
}

func (h *handlerAuth) Authorization(ctx context.Context, event awsEvents.APIGatewayCustomAuthorizerRequest) (awsEvents.APIGatewayCustomAuthorizerResponse, error) {
	token := event.AuthorizationToken
	statusCode, err := h.jwtHf.ValidateToken(token, []byte(os.Getenv("JWT_SIGIN_KEY")))
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("error: %v", err)
	}

	if statusCode != 200 {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")

	}
	return generatePolicy("user", "Allow", event.MethodArn), nil
}

func generatePolicy(principalId, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	authResponse.Context = map[string]interface{}{
		"status": "OK",
	}
	return authResponse
}
