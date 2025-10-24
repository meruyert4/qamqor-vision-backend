module auth-service

go 1.21

require (
	github.com/go-playground/validator/v10 v10.14.0
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.3.1
	github.com/joho/godotenv v1.5.1
	github.com/lib/pq v1.10.9
	github.com/meruyert4/qamqor-vision-backend/proto/auth v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.17.0
	google.golang.org/grpc v1.59.0
)

replace github.com/meruyert4/qamqor-vision-backend/proto/auth => ../proto/auth

require (
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231212172506-995d672761c0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
