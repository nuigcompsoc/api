package server

import (
	"errors"
	"fmt"
	"net/http"
	"github.com/rs/cors"
	"github.com/nuigcompsoc/api/internal/config"
)

type Server struct {
	config config.Config
	http *http.Server
}

// NewServer returns an initialized Server
func NewServer(config config.Config) *Server {
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: config.HTTP.CORS.AllowedOrigins,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	r := SetupRouter()
	httpSrv := &http.Server{
		Addr:    config.HTTP.ListenAddress + ":" + config.HTTP.ListenPort,
		Handler: corsMiddleware.Handler(r),
	}

	s := &Server{
		config: config,
		http: httpSrv,
	}

	// v1 route
	v1 := r.Group("v1")
	s.v1Router(v1)

	return s
}

// Start begins listening
func (s *Server) Start() error {
	var err error
	if err = s.http.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	return nil
}

// Stop shuts down the server and listener
func (s *Server) Stop() error {
	if err := s.http.Close(); err != nil {
		return fmt.Errorf("failed to stop HTTP server: %w", err)
	}

	return nil
}