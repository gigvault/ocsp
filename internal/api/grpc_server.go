package api

import (
	"context"
	"time"

	"github.com/gigvault/shared/api/proto/ocsp"
	"github.com/gigvault/shared/pkg/logger"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// OCSPGRPCServer implements the OCSP gRPC service
type OCSPGRPCServer struct {
	ocsp.UnimplementedOCSPServiceServer
	db     *pgxpool.Pool
	logger *logger.Logger
}

// NewOCSPGRPCServer creates a new OCSP gRPC server
func NewOCSPGRPCServer(db *pgxpool.Pool) *OCSPGRPCServer {
	return &OCSPGRPCServer{
		db:     db,
		logger: logger.Global(),
	}
}

// UpdateStatus updates the status of a certificate
func (s *OCSPGRPCServer) UpdateStatus(ctx context.Context, req *ocsp.UpdateStatusRequest) (*ocsp.UpdateStatusResponse, error) {
	s.logger.Info("Received UpdateStatus request",
		zap.String("serial", req.SerialNumber),
		zap.String("status", req.Status),
	)

	// Validate input
	if req.SerialNumber == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}
	if req.Status == "" {
		req.Status = "good"
	}

	// Validate status value
	if req.Status != "good" && req.Status != "revoked" && req.Status != "unknown" {
		return nil, status.Error(codes.InvalidArgument, "invalid status (must be: good, revoked, or unknown)")
	}

	// Insert or update OCSP status
	query := `
		INSERT INTO ocsp_responses (serial, status, this_update, next_update, revoked_at, revocation_reason)
		VALUES ($1, $2, NOW(), NOW() + INTERVAL '24 hours', $3, $4)
		ON CONFLICT (serial) DO UPDATE SET
			status = EXCLUDED.status,
			this_update = NOW(),
			next_update = NOW() + INTERVAL '24 hours',
			revoked_at = EXCLUDED.revoked_at,
			revocation_reason = EXCLUDED.revocation_reason
	`

	var revokedAt *time.Time
	if req.Status == "revoked" && req.RevokedAt != nil {
		t := req.RevokedAt.AsTime()
		revokedAt = &t
	}

	_, err := s.db.Exec(ctx, query,
		req.SerialNumber,
		req.Status,
		revokedAt,
		req.RevocationReason,
	)
	if err != nil {
		s.logger.Error("Failed to update OCSP status", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to update status")
	}

	s.logger.Info("OCSP status updated", zap.String("serial", req.SerialNumber))

	return &ocsp.UpdateStatusResponse{
		Success: true,
		Message: "status updated successfully",
	}, nil
}

// CheckStatus checks the status of a certificate
func (s *OCSPGRPCServer) CheckStatus(ctx context.Context, req *ocsp.CheckStatusRequest) (*ocsp.CheckStatusResponse, error) {
	s.logger.Info("Received CheckStatus request", zap.String("serial", req.SerialNumber))

	if req.SerialNumber == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	// Query OCSP status
	query := `
		SELECT status, this_update, next_update, revoked_at, revocation_reason
		FROM ocsp_responses
		WHERE serial = $1
	`

	var statusStr, revocationReason string
	var thisUpdate, nextUpdate time.Time
	var revokedAt *time.Time

	err := s.db.QueryRow(ctx, query, req.SerialNumber).Scan(
		&statusStr,
		&thisUpdate,
		&nextUpdate,
		&revokedAt,
		&revocationReason,
	)
	if err != nil {
		// Certificate not found - return unknown status
		s.logger.Warn("Certificate status not found", zap.String("serial", req.SerialNumber))
		return &ocsp.CheckStatusResponse{
			Status:     "unknown",
			ThisUpdate: timestamppb.Now(),
			NextUpdate: timestamppb.New(time.Now().Add(24 * time.Hour)),
		}, nil
	}

	resp := &ocsp.CheckStatusResponse{
		Status:     statusStr,
		ThisUpdate: timestamppb.New(thisUpdate),
		NextUpdate: timestamppb.New(nextUpdate),
	}

	if revokedAt != nil {
		resp.RevokedAt = timestamppb.New(*revokedAt)
		resp.RevocationReason = revocationReason
	}

	s.logger.Info("OCSP status checked",
		zap.String("serial", req.SerialNumber),
		zap.String("status", statusStr),
	)

	return resp, nil
}

// BatchUpdateStatus updates status for multiple certificates
func (s *OCSPGRPCServer) BatchUpdateStatus(ctx context.Context, req *ocsp.BatchUpdateStatusRequest) (*ocsp.BatchUpdateStatusResponse, error) {
	s.logger.Info("Received BatchUpdateStatus request", zap.Int("count", len(req.Updates)))

	successCount := 0
	failureCount := 0
	var errors []string

	for _, update := range req.Updates {
		_, err := s.UpdateStatus(ctx, update)
		if err != nil {
			failureCount++
			errors = append(errors, err.Error())
		} else {
			successCount++
		}
	}

	s.logger.Info("Batch update completed",
		zap.Int("success", successCount),
		zap.Int("failure", failureCount),
	)

	return &ocsp.BatchUpdateStatusResponse{
		SuccessCount: int32(successCount),
		FailureCount: int32(failureCount),
		Errors:       errors,
	}, nil
}
