package sbi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/bsf/pkg/app"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/metrics"
)

type Server struct {
	app.App

	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(bsf app.App, tlsKeyLogPath string) (*Server, error) {
	cfg := bsf.Config()
	if cfg == nil || cfg.Configuration == nil || cfg.Configuration.Sbi == nil {
		return nil, errors.New("SBI configuration is required")
	}
	sbiCfg := cfg.Configuration.Sbi
	switch sbiCfg.Scheme {
	case "http":
	case "https":
		if sbiCfg.Tls == nil {
			return nil, errors.New("TLS configuration is required for HTTPS")
		}
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", sbiCfg.Scheme)
	}
	s := &Server{App: bsf}
	s.router = newRouter()
	bindAddr := fmt.Sprintf("%s:%d", sbiCfg.BindingIPv4, sbiCfg.Port)
	var err error
	s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router, cfg.GetIdleTimeout())
	if err != nil {
		return nil, err
	}
	s.httpServer.ReadTimeout = 10 * time.Second
	s.httpServer.WriteTimeout = 10 * time.Second
	s.httpServer.MaxHeaderBytes = 1 << 20
	s.httpServer.ErrorLog = log.New(logger.SbiLog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)
	return s, nil
}

func newRouter() *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)
	router.Use(metrics.InboundMetrics())
	router.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  false,
		AllowOriginFunc:  func(origin string) bool { return true },
		MaxAge:           86400,
	}))
	AddService(router)
	return router
}

func (s *Server) Run(_ context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go s.startServer(wg)
	return nil
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		logger.SbiLog.Errorf("Could not close SBI server: %v", err)
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			logger.SbiLog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
			s.Terminate()
		}
		wg.Done()
	}()
	logger.SbiLog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)
	var err error
	sbiCfg := s.Config().Configuration.Sbi
	switch sbiCfg.Scheme {
	case "http":
		err = s.httpServer.ListenAndServe()
	case "https":
		err = s.httpServer.ListenAndServeTLS(sbiCfg.Tls.Pem, sbiCfg.Tls.Key)
	default:
		err = fmt.Errorf("unsupported scheme: %s", sbiCfg.Scheme)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.SbiLog.Errorf("SBI server error: %v", err)
		s.Terminate()
	}
	logger.SbiLog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
