package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rikkimongoose/wiregock"
	actuator "github.com/sinhashubham95/go-actuator"
	"go.uber.org/zap"
)

type WiregockServer struct {
	router   *mux.Router
	config   ServerConfig
	log      *zap.Logger
	srv      *http.Server
	srvHttps *http.Server
}

func CreateWiregockServer(router *mux.Router, config ServerConfig, log *zap.Logger) WiregockServer {
	return WiregockServer{mux.NewRouter(), config, log, nil, nil}
}

type HandlerFactory interface {
	Install(router *mux.Router)
}

func (server WiregockServer) Install(handlerFactory HandlerFactory) WiregockServer {
	handlerFactory.Install(server.router)
	return server
}

func (server WiregockServer) Start() {
	serverAddr := fmt.Sprintf("%s:%d", server.config.Host, server.config.Port)
	server.log.Info("Starting up", zap.String("server", serverAddr))
	server.srv = &http.Server{
		Handler: server.router,
		Addr:    serverAddr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: time.Duration(server.config.WriteTimeoutSec),
		ReadTimeout:  time.Duration(server.config.ReadTimeoutSec),
	}
	err := server.srv.ListenAndServe()
	if err != nil {
		server.log.Error(`Error starting server`,
			zap.Error(err),
			zap.String("host", server.config.Host),
			zap.Int("port", server.config.Port))
	}
	if server.config.Https {
		serverHttpsAddr := fmt.Sprintf("%s:%d", server.config.Host, server.config.PortHttps)
		server.log.Info("Starting up HTTPS", zap.String("server", serverHttpsAddr))
		server.srv = &http.Server{
			Handler: server.router,
			Addr:    serverHttpsAddr,
			// Good practice: enforce timeouts for servers you create!
			WriteTimeout: time.Duration(server.config.WriteTimeoutSec),
			ReadTimeout:  time.Duration(server.config.ReadTimeoutSec),
		}
		err := server.srv.ListenAndServeTLS(server.config.CertFile, server.config.KeyFile)
		if err != nil {
			server.log.Error(`Error starting server`,
				zap.Error(err),
				zap.String("host", server.config.Host),
				zap.Int("port", server.config.PortHttps),
				zap.String("certFile", server.config.CertFile),
				zap.String("keyFile", server.config.KeyFile))
		}
	}
}

func (server WiregockServer) Stop() {
	servers := []*http.Server{server.srv, server.srvHttps}
	for _, serverItem := range servers {
		if serverItem != nil {
			// Stopping the server
			// Setting up signal capturing
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			// Waiting for SIGINT (kill -2)
			<-stop

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := serverItem.Shutdown(ctx); err != nil {
				server.log.Error(`Error stopping server`, zap.Error(err))
			}
		}
	}
	server.srv = nil
	server.srvHttps = nil
}

type ActuatorHandler struct {
	Port int
}

func (handler ActuatorHandler) Install(router *mux.Router) {
	actuatorConfig := &actuator.Config{
		Endpoints: []int{
			actuator.Env,
			actuator.Info,
			actuator.Metrics,
			actuator.Ping,
			actuator.Shutdown,
			actuator.ThreadDump,
		},
		Name:    productName,
		Port:    handler.Port,
		Version: productVersion,
	}
	actuatorHandler := actuator.GetActuatorHandler(actuatorConfig)
	router.PathPrefix("/actuator/").Handler(actuatorHandler)
}

type HealthcheckHandler struct {
	Response string
}

func (handler HealthcheckHandler) Install(router *mux.Router) {
	router.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(handler.Response))
	}).Methods("GET", "HEAD")
}

type MocksInfoHandler struct {
	mocks []wiregock.MockData
}

func (handler MocksInfoHandler) Install(router *mux.Router) {
	router.HandleFunc("/mocks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(handler.mocks)
	}).Methods("GET")
}

type MocksHandler struct {
	mocks           []wiregock.MockData
	dataLoader      DataLoader
	mustacheService MustacheService
	config          MocksHandlerConfig
	log             *zap.Logger
}

type MocksHandlerConfig struct {
	MultipartBuffSizeBytes int64
}

func (mocksHandler MocksHandler) Install(router *mux.Router) {
	for _, mock := range mocksHandler.mocks {
		methods := wiregock.LoadMethods(*mock.Request.Method)
		if len(methods) == 0 {
			mocksHandler.log.Warn(`No method defined for mock. Default method GET is used`)
			methods = []string{"GET"}
		}
		handler := mocksHandler.GenerateHandler(&mock)
		if mock.Request.BasicAuthCredentials != nil && mock.Request.BasicAuthCredentials.Username != nil && mock.Request.BasicAuthCredentials.Password != nil {
			handler = mocksHandler.basicAuth(BasicAuthConfig{handler, *mock.Request.BasicAuthCredentials.Username, *mock.Request.BasicAuthCredentials.Password})
		}
		var url string
		if mock.Request.UrlPath != nil {
			url = *mock.Request.UrlPath
		} else if mock.Request.UrlPattern != nil {
			url = *mock.Request.UrlPattern
		} else {
			mocksHandler.log.Warn(`No url defined for mock. Default url is used`)
			url = "/"
		}
		router.PathPrefix(url).Handler(handler).Methods(methods...)
	}
}

type BasicAuthConfig struct {
	next     http.HandlerFunc
	username string
	password string
}

func (mocksHandler MocksHandler) basicAuth(config BasicAuthConfig) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		usernameExpected, passwordExpected, ok := r.BasicAuth()
		if ok {
			// Calculate SHA-256 hashes for the provided and expected
			// usernames and passwords.
			usernameHash := sha256.Sum256([]byte(config.username))
			passwordHash := sha256.Sum256([]byte(config.password))
			expectedUsernameHash := sha256.Sum256([]byte(usernameExpected))
			expectedPasswordHash := sha256.Sum256([]byte(passwordExpected))

			// Use the subtle.ConstantTimeCompare() function to check if
			// the provided username and password hashes equal the
			// expected username and password hashes. ConstantTimeCompare
			// will return 1 if the values are equal, or 0 otherwise.
			// Importantly, we should to do the work to evaluate both the
			// username and password before checking the return values to
			// avoid leaking information.
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			// If the username and password are correct, then call
			// the next handler in the chain. Make sure to return
			// afterwards, so that none of the code below is run.
			if usernameMatch && passwordMatch {
				config.next.ServeHTTP(w, r)
				return
			}
		}

		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func (mocksHandler MocksHandler) GenerateHandler(mock *wiregock.MockData) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		multipartFiles := []wiregock.FileFormData{}
		dc := wiregock.DataContext{
			Body: func() string {
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return ""
				}
				return string(b[:])
			},
			Get: func(key string) string {
				return req.Header.Get(key)
			},
			GetMulti: func(key string) []string {
				return req.Header.Values(key)
			},
			Params: func(key string) string {
				return req.URL.Query().Get(key)
			},
			ParamsMulti: func(key string) []string {
				return req.URL.Query()[key]
			},
			FormValue: func(key string) string {
				return req.FormValue(key)
			},
			MultipartForm: func() []wiregock.FileFormData {
				return multipartFiles
			},
			Cookies: func(key string) string {
				cookie, err := req.Cookie(key)
				if err != nil {
					return ""
				}
				return cookie.Value
			},
		}
		parsedCondition, err := wiregock.ParseCondition(mock.Request, &dc)
		if err != nil {
			http.Error(w, "Wrong condition", http.StatusInternalServerError)
			return
		}
		if parsedCondition.IsMultipart {
			multipartFilesLoaded, err := mocksHandler.loadMultipartFiles(req)
			if err != nil {
				http.Error(w, "Unable to parse multipart files", http.StatusInternalServerError)
				return
			}
			multipartFiles = append(multipartFiles, multipartFilesLoaded...)
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.NotFound(w, req)
			return
		}
		result, err := parsedCondition.Condition.Check()
		if err != nil {
			http.Error(w, "Error with rule execution", http.StatusInternalServerError)
			return
		}
		if !result {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}

		traceId := req.Header.Get("traceparent")
		if strings.Compare(traceId, "") == 0 {
			w.Header().Set("traceparent", wiregock.GenerateTraceparent())
		} else {
			w.Header().Set("traceparent", traceId)
		}

		response := mock.Response
		if response == nil {
			return
		}
		if response.Headers != nil {
			for key, value := range response.Headers {
				w.Header().Set(key, value)
			}
		}

		if response.Cookies != nil {
			for key, value := range response.Cookies {
				cookie := http.Cookie{
					Name:     key,
					Value:    value,
					Path:     "/",
					MaxAge:   3600,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, &cookie)
			}
		}

		requestData, err := wiregock.LoadRequestData(req)
		if err != nil {
			mocksHandler.log.Error("Load template data from request", zap.Error(err))
			http.Error(w, "Error loading template data from request", http.StatusInternalServerError)
			return
		}

		statusCode := http.StatusOK
		if response.Status != nil {
			statusCode = *response.Status
		}
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
		}

		if response.BodyFileName != nil {
			bodyFileName := *response.BodyFileName
			if requestData != nil {
				bodyFileName = mocksHandler.mustacheService.replace(w, bodyFileName, requestData)
			}
			bodyFileText := mocksHandler.dataLoader.readString(bodyFileName)
			if err != nil {
				flusher.Flush()
				bodyFileData := mocksHandler.mustacheService.replace(w, bodyFileText, requestData)
				io.WriteString(w, bodyFileData)
			}
		}

		if response.Body != nil {
			responseBody := *response.Body
			if requestData != nil {
				responseBody = mocksHandler.mustacheService.replace(w, responseBody, requestData)
			}
			flusher.Flush()
			io.WriteString(w, responseBody)
		}
	}
}

func (mocksHandler MocksHandler) loadMultipartFiles(req *http.Request) ([]wiregock.FileFormData, error) {
	if req.MultipartForm == nil {
		err := req.ParseMultipartForm(mocksHandler.config.MultipartBuffSizeBytes)
		if err != nil {
			return nil, err
		}
	}
	fileFormDatas := []wiregock.FileFormData{}
	for _, formFiles := range req.MultipartForm.File {
		for _, formFile := range formFiles {
			b, errInner := formFile.Open()
			if errInner != nil {
				mocksHandler.log.Error("Unable to load multipart file", zap.Error(errInner), zap.String("file", formFile.Filename))
				continue
			}
			sliceByte, errInner := io.ReadAll(b)
			if errInner != nil {
				mocksHandler.log.Error("Unable to parse multipart file", zap.Error(errInner), zap.String("file", formFile.Filename))
				continue
			}
			fileFormData := wiregock.FileFormData{
				FileName: formFile.Filename,
				Headers:  formFile.Header,
				Data:     string(sliceByte),
			}
			fileFormDatas = append(fileFormDatas, fileFormData)
		}
	}
	return fileFormDatas, nil
}
