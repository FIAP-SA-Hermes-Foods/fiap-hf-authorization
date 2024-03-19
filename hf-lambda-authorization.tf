provider "aws" {
  region = "us-east-1"
}

resource "aws_lambda_function" "hf_lambda" {
  function_name = "hf-api-authorization-func"
  handler       = "hf-auth"
  runtime       = "provided.al2"
  timeout       = 10 // tempo limite em segundos
  memory_size   = 128 // tamanho da memória em MB
  filename      = "hf_api_authorization_lambda.zip" // arquivo zipado com o código da função
  source_code_hash = filebase64sha256("hf_api_authorization_lambda.zip") // hash do arquivo zipado
  // Permissões para invocar a função
  role = "{{LAMBDA_EXEC_PERM}}"
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda-exec-role-authorization"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action   = [
            "sts:AssumeRole",
            "lambda:*"
        ]
        Resource = "arn:aws:lambda:*:*:*"      
       }
    ]
  })
}
