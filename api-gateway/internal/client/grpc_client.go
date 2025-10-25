package client

import (
	"context"

	pb "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type AuthClient struct {
	client pb.AuthServiceClient
	conn   *grpc.ClientConn
}

func NewAuthClient(authServiceAddr string) (*AuthClient, error) {
	conn, err := grpc.Dial(authServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := pb.NewAuthServiceClient(conn)

	return &AuthClient{
		client: client,
		conn:   conn,
	}, nil
}

func (c *AuthClient) Close() error {
	return c.conn.Close()
}

// propagateHeaders copies specific headers from incoming context to outgoing gRPC context
func (c *AuthClient) propagateHeaders(ctx context.Context) context.Context {
	md := metadata.New(nil)

	// Try to get headers from incoming Gin context
	if headers, ok := ctx.Value("headers").(map[string][]string); ok {
		for key, values := range headers {
			// Convert header keys to lowercase for gRPC metadata
			if key == "Authorization" || key == "authorization" {
				md.Set("authorization", values...)
			}
		}
	}

	return metadata.NewOutgoingContext(ctx, md)
}

func (c *AuthClient) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	return c.client.CreateUser(ctx, req)
}

func (c *AuthClient) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	return c.client.Login(ctx, req)
}

func (c *AuthClient) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	return c.client.GetUser(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	return c.client.UpdateUser(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	return c.client.ChangePassword(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	return c.client.DeleteUser(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) VerifyUser(ctx context.Context, req *pb.VerifyUserRequest) (*pb.VerifyUserResponse, error) {
	return c.client.VerifyUser(ctx, req)
}

func (c *AuthClient) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	return c.client.ForgotPassword(ctx, req)
}

func (c *AuthClient) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	return c.client.ResetPassword(ctx, req)
}

func (c *AuthClient) GetUserLoginHistory(ctx context.Context, req *pb.GetUserLoginHistoryRequest) (*pb.GetUserLoginHistoryResponse, error) {
	return c.client.GetUserLoginHistory(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) GetRecentLoginHistory(ctx context.Context, req *pb.GetRecentLoginHistoryRequest) (*pb.GetRecentLoginHistoryResponse, error) {
	return c.client.GetRecentLoginHistory(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) GetFailedLoginAttempts(ctx context.Context, req *pb.GetFailedLoginAttemptsRequest) (*pb.GetFailedLoginAttemptsResponse, error) {
	return c.client.GetFailedLoginAttempts(c.propagateHeaders(ctx), req)
}

func (c *AuthClient) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	return c.client.ValidateToken(ctx, req)
}
