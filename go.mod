module github.com/gigvault/ocsp

go 1.24.0

require (
	github.com/gigvault/shared v1.2.0
	github.com/gorilla/mux v1.8.1
	github.com/jackc/pgx/v5 v5.5.0
	go.uber.org/zap v1.26.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/gigvault/shared => ../shared
