package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/rikkimongoose/wiregock"
	actuator "github.com/sinhashubham95/go-actuator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	productName    = "WireGock"
	productVersion = "0.10.6"
)

type AppConfig struct {
	Server struct {
		Host                   string `yaml:"host,omitempty" env:"SERVER_HOST" env-default:"localhost" env-description:"server host"`
		Port                   int    `yaml:"port,omitempty" env:"SERVER_PORT" env-default:"8080" env-description:"server port"`
		MultipartBuffSizeBytes int64  `yaml:"multipartBuffSizeBytes,omitempty" env:"MULTIPART_BUFF_SIZE" env-default:"33554432" env-description:"max multipart file size allowed"`
		WriteTimeoutSec        int    `yaml:"writeTimeoutSec,omitempty" env:"WRITE_TIMEOUT_SEC" env-default:"15" env-description:"max duration before timing out writes of the response"`
		ReadTimeoutSec         int    `yaml:"readTimeoutSec,omitempty" env:"READ_TIMEOUT_SEC" env-default:"15" env-description:"max duration for reading the entire request"`
	} `json:"server,omitempty" yaml:"server,omitempty"`
	Mongo *struct {
		Url        string   `json:"url,omitempty" yaml:"url,omitempty" env:"MONGO_URL" env-default:"mongodb://localhost:27017" env-description:"MongoDB connection string"`
		Database   string   `json:"db,omitempty" yaml:"db,omitempty" env:"MONGO_DB" env-default:"local" env-description:"MongoDB database"`
		Collection []string `json:"collection,omitempty" yaml:"collection,omitempty" env:"MONGO_COLLECTION" env-default:"mock" env-description:"MongoDB collection"`
		CaFile     string   `json:"caFile,omitempty" yaml:"caFile,omitempty" env:"MONGO_CA" env-default:"" env-description:"path to CA certificate"`
		CertFile   string   `json:"certFile,omitempty" yaml:"certFile,omitempty" env:"MONGO_CERT" env-default:"" env-description:"path to public client certificate"`
		KeyFile    string   `json:"keyFile,omitempty" yaml:"keyFile,omitempty" env:"MONGO_KEY" env-default:"" env-description:"path to private client key"`
	} `json:"mongo,omitempty" yaml:"mongo,omitempty"`
	FileSource *struct {
		Files []string `json:"mockfiles,omitempty" yaml:"mockfiles,omitempty" env:"MOCKFILES_COLLECTION" env-default:"" env-description:"JSON source files"`
		Dir   *string  `json:"dir,omitempty" yaml:"dir,omitempty" env-default:"./" env:"MOCKFILES_DIR" env-description:"Directory with mock files"`
		Mask  *string  `json:"mask,omitempty" yaml:"mask,omitempty" env-default:"*.json" env:"MOCKFILES_MASK" env-description:"Mask for mock files"`
	} `json:"filesource,omitempty" yaml:"filesource,omitempty"`
	Log struct {
		Level            *string  `json:"level,omitempty" yaml:"level,omitempty" env-default:"json" env:"LOG_LEVEL" env-description:"log output level: Debug, Info, Warn, Error, DPanic, Panic, Fatal"`
		Encoding         string   `json:"encoding,omitempty" yaml:"encoding,omitempty" env-default:"json" env:"LOG_ENCODING" env-description:"storage format for logs"`
		OutputPaths      []string `json:"output,omitempty" yaml:"output,omitempty" env-default:"stdout,/tmp/logs" env:"LOG_OUTPUTPATH" env-description:"output pipelines for logs"`
		ErrorOutputPaths []string `json:"erroutput,omitempty" yaml:"erroutput,omitempty" env-default:"stderr" env:"LOG_OUTPUTERRORPATH" env-description:"error pipelines for logs"`
	} `json:"log,omitempty" yaml:"log,omitempty"`
}

type MockRoutesData struct {
	MockRoutes []MockRoute `json:"mockRoutes,omitempty"`
}

type MockRoute struct {
	Mocks []wiregock.MockData `json:"mocks,omitempty"`
}

var log *zap.Logger
var config AppConfig
var mocksRoutesFiles *MockRoutesData
var mockRoutesDataFromMongo *MockRoutesData

func main() {
	var err error
	cfgPath := *flag.String("CONFIG", "config.yml", "Path to application config file")
	err = cleanenv.ReadConfig(cfgPath, &config)
	if err != nil {
		panic(fmt.Sprintf("Unable to load config file %s. Error: %s", cfgPath, err))
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	zc := zap.Config{
		Level:            zap.NewAtomicLevelAt(parseLogLevel(config.Log.Level)),
		OutputPaths:      config.Log.OutputPaths,
		ErrorOutputPaths: config.Log.ErrorOutputPaths,
		EncoderConfig:    encoderCfg,
		Encoding:         config.Log.Encoding,
		InitialFields: map[string]interface{}{
			"pid": os.Getpid(),
		},
	}
	log = zap.Must(zc.Build())

	defer log.Sync() // все асинхронные логи будут записаны перед выходом

	router := mux.NewRouter()
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
		Port:    config.Server.Port,
		Version: productVersion,
	}
	actuatorHandler := actuator.GetActuatorHandler(actuatorConfig)
	router.PathPrefix("/actuator/").Handler(actuatorHandler)

	filesSource := []string{}
	dir, mask := "./", "*.json"
	if config.FileSource != nil {
		if config.FileSource.Dir != nil {
			dir = *config.FileSource.Dir
		}
		if config.FileSource.Mask != nil {
			mask = *config.FileSource.Mask
		}
		if len(config.FileSource.Files) != 0 {
			filesSource = append(filesSource, config.FileSource.Files...)
		}
	}
	foundMockfiles, err := findInDir(dir, mask)
	if err != nil {
		log.Error(`Unable to search files by mask.`,
			zap.Error(err),
			zap.String("dir", dir),
			zap.String("mask", mask),
		)
	} else {
		filesSource = append(filesSource, foundMockfiles...)
	}

	if len(filesSource) != 0 {
		var mockRoutes []MockRoute
		for _, file := range filesSource {
			jsonFile, err := os.Open(file)
			if err != nil {
				log.Error(`Error loading JSON from file`, zap.Error(err), zap.String("file", file))
				continue
			}
			defer jsonFile.Close()
			byteValue, _ := io.ReadAll(jsonFile)
			var mocks []wiregock.MockData
			err = json.Unmarshal(byteValue, &mocks)
			if err != nil {
				log.Warn(`Unable to parse JSON array from file. Attempt to read as single value`, zap.Error(err), zap.String("file", file))
				var mockSingle wiregock.MockData
				err = json.Unmarshal([]byte(byteValue), &mockSingle)
				if err != nil {
					log.Error(`Error parsing JSON single mock from file.`, zap.Error(err), zap.String("file", file))
					continue
				}
				mocks = append(mocks, mockSingle)
			}
			mockRoutes = append(mockRoutes, MockRoute{mocks})
			for _, mock := range mocks {
				log.Info(`Successfully load route from file`, zap.String("urlPath", *mock.Request.UrlPath), zap.String("file", file))
			}
		}
		if len(mockRoutes) > 0 {
			mocksRoutesFiles = &MockRoutesData{mockRoutes}
			installMockRoutesData(mocksRoutesFiles, router)
		}
	}

	if config.Mongo != nil {
		mockRoutesDataFromMongo = loadMocksFromMongo(
			config.Mongo.Url,
			config.Mongo.Database,
			config.Mongo.Collection,
			config.Mongo.CaFile,
			config.Mongo.CertFile,
			config.Mongo.KeyFile)
		if mockRoutesDataFromMongo != nil {
			installMockRoutesData(mockRoutesDataFromMongo, router)
		}
	}

	mocks := []wiregock.MockData{}
	if mockRoutesDataFromMongo != nil {
		for _, mockRoute := range mockRoutesDataFromMongo.MockRoutes {
			mocks = append(mocks, mockRoute.Mocks...)
		}
	}
	if mocksRoutesFiles != nil {
		for _, mockRoute := range mocksRoutesFiles.MockRoutes {
			mocks = append(mocks, mockRoute.Mocks...)
		}
	}
	router.HandleFunc("/mocks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mocks)
	}).Methods("GET")

	router.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}).Methods("GET", "HEAD")
	serverAddr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	log.Info("Starting up", zap.String("server", serverAddr))
	srv := &http.Server{
		Handler: router,
		Addr:    serverAddr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: time.Duration(config.Server.WriteTimeoutSec),
		ReadTimeout:  time.Duration(config.Server.ReadTimeoutSec),
	}
	err = srv.ListenAndServe()
	if err != nil {
		log.Error(`Error starting server`,
			zap.Error(err),
			zap.String("host", config.Server.Host),
			zap.Int("port", config.Server.Port))
	}
}

func installMockRoutesData(mockRoutesData *MockRoutesData, router *mux.Router) {
	for _, mockRoute := range mockRoutesData.MockRoutes {
		for _, mock := range mockRoute.Mocks {
			methods := wiregock.LoadMethods(*mock.Request.Method)
			handler := generateHandler(&mock)
			if mock.Request.BasicAuthCredentials != nil && mock.Request.BasicAuthCredentials.Username != nil && mock.Request.BasicAuthCredentials.Password != nil {
				handler = basicAuth(handler, *mock.Request.BasicAuthCredentials.Username, *mock.Request.BasicAuthCredentials.Password)
			}
			var url string
			if mock.Request.UrlPath != nil {
				url = *mock.Request.UrlPath
			} else if mock.Request.UrlPattern != nil {
				url = *mock.Request.UrlPattern
			} else {
				log.Warn(`No url defined for mock`)
				continue
			}

			router.PathPrefix(url).Handler(handler).Methods(methods...)
		}
	}
}

func loadMocksFromMongo(url string, db string, storages []string, caFile string, certFile string, keyFile string) *MockRoutesData {
	ctx := context.TODO()
	opts := options.Client().ApplyURI(config.Mongo.Url)
	tlsConfig := mongoTlsConfig(caFile, certFile, keyFile)
	if tlsConfig != nil {
		opts = opts.SetTLSConfig(tlsConfig)
	}

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		log.Error(`Database connection error`, zap.Error(err), zap.String("db", url))
		return nil
	}

	var resultPing bson.M
	if err := client.Database(config.Mongo.Database).RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Decode(&resultPing); err != nil {
		log.Error(`Database ping error`, zap.Error(err), zap.String("db", db))
		return nil
	}

	log.Info("Pinged your deployment. You successfully connected to MongoDB!")

	var mockRoutes []MockRoute
	for _, storage := range storages {
		mockRoute := loadMock(db, client, &ctx, storage)
		if mockRoute != nil {
			mockRoutes = append(mockRoutes, *mockRoute)
		}
	}

	return &MockRoutesData{mockRoutes}
}

func loadMock(db string, client *mongo.Client, ctx *context.Context, mockSource string) *MockRoute {
	var mocks []wiregock.MockData
	wiregockCollection := client.Database(db).Collection(mockSource)
	cursor, err := wiregockCollection.Find(*ctx, bson.M{})
	if err != nil {
		log.Error(`Database cursor creation error`,
			zap.Error(err),
			zap.String("db", db),
			zap.String("collection", mockSource))
		return nil
	}
	for cursor.Next(*ctx) {
		var mock wiregock.MockData
		if err = cursor.Decode(&mock); err != nil {
			log.Error(`Unable to parse MockData`, zap.Error(err))
			continue
		}
		if mock.Request.UrlPath != nil {
			log.Info(`Rule loaded`, zap.String("url", *mock.Request.UrlPath))
		} else if mock.Request.UrlPattern != nil {
			log.Info(`Rule loaded`, zap.String("url regex", *mock.Request.UrlPattern))
		} else {
			log.Info(`Rule loaded, but no URL to attach`)
		}
		mocks = append(mocks, mock)
	}
	return &MockRoute{mocks}
}

func loadMultipartFiles(req *http.Request) ([]wiregock.FileFormData, error) {
	if req.MultipartForm == nil {
		err := req.ParseMultipartForm(config.Server.MultipartBuffSizeBytes)
		if err != nil {
			return nil, err
		}
	}
	fileFormDatas := []wiregock.FileFormData{}
	for _, formFiles := range req.MultipartForm.File {
		for _, formFile := range formFiles {
			b, errInner := formFile.Open()
			if errInner != nil {
				log.Error("Unable to load multipart file", zap.Error(errInner), zap.String("file", formFile.Filename))
				continue
			}
			sliceByte, errInner := io.ReadAll(b)
			if errInner != nil {
				log.Error("Unable to parse multipart file", zap.Error(errInner), zap.String("file", formFile.Filename))
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

func generateHandler(mock *wiregock.MockData) http.HandlerFunc {
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
			multipartFilesLoaded, err := loadMultipartFiles(req)
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
			log.Error("Load template data from request", zap.Error(err))
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
				bodyFileName = replaceMustache(w, bodyFileName, requestData)
			}
			bodyFile, err := os.Open(bodyFileName)
			if err == nil {
				byteValue, err := io.ReadAll(bodyFile)
				if err == nil {
					flusher.Flush()
					bodyFileData := replaceMustache(w, string(byteValue), requestData)
					io.WriteString(w, bodyFileData)
				} else {
					log.Error(`Error reading all data from response file`, zap.Error(err), zap.String("file", bodyFileName))
				}
			} else {
				log.Error(`Error loading data from response file`, zap.Error(err), zap.String("file", bodyFileName))
			}
			defer bodyFile.Close()
		}

		if response.Body != nil {
			responseBody := *response.Body
			if requestData != nil {
				responseBody = replaceMustache(w, responseBody, requestData)
			}
			flusher.Flush()
			io.WriteString(w, responseBody)
		}

	}
}

func replaceMustache(w http.ResponseWriter, body string, context ...interface{}) string {
	result, err := mustache.Render(body, context)
	if err == nil {
		fileLinksList := wiregock.LoadFileLinksList(result)
		if len(fileLinksList) > 0 {
			filesDataMap := loadFilesData(fileLinksList)
			if len(filesDataMap) > 0 {
				filesDataMap := updateMustacheDataInFiles(filesDataMap, context)
				result = wiregock.UpdateFileLinks(body, filesDataMap)
			}
		}
		return result
	}
	log.Error("Implementing template data to responseBody", zap.Error(err))
	if w != nil {
		http.Error(w, "Error implementing template data to responseBody", http.StatusInternalServerError)
	}
	return body
}

func loadFilesData(fileNames []string) map[string]string {
	resultMap := make(map[string]string)
	for _, fileName := range fileNames {
		b, err := os.ReadFile(fileName)
		if err != nil {
			log.Warn("Unable to load data from file, mentioned in template", zap.Error(err), zap.String("templateFileName", fileName))
			continue
		}
		resultMap[fileName] = string(b)
	}
	return resultMap
}

func updateMustacheDataInFiles(dataMap map[string]string, context ...interface{}) map[string]string {
	resultMap := make(map[string]string)
	for fileName, fileSource := range dataMap {
		result, err := mustache.Render(fileSource, context)
		if err != nil {
			log.Warn("Wrong mustache template in file.", zap.Error(err), zap.String("templateFileName", fileName))
			resultMap[fileName] = fileSource
		}
		resultMap[fileName] = result
	}
	return resultMap
}

func parseLogLevel(logLevel *string) zapcore.Level {
	defaultLevel := zapcore.InfoLevel
	if logLevel == nil {
		return defaultLevel
	}
	logLevelStr := *logLevel
	switch {
	case logLevelStr == "Debug":
		return zapcore.DebugLevel
	// InfoLevel is the default logging priority.
	case logLevelStr == "Info":
		return zapcore.InfoLevel
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	case logLevelStr == "Warn":
		return zapcore.WarnLevel
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	case logLevelStr == "Error":
		return zapcore.ErrorLevel
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	case logLevelStr == "DPanic":
		return zapcore.DPanicLevel
	// PanicLevel logs a message, then panics.
	case logLevelStr == "Panic":
		return zapcore.PanicLevel
	// FatalLevel logs a message, then calls os.Exit(1).
	case logLevelStr == "Fatal":
		return zapcore.FatalLevel
	}
	return defaultLevel
}

func basicAuth(next http.HandlerFunc, username string, password string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		usernameExpected, passwordExpected, ok := r.BasicAuth()
		if ok {
			// Calculate SHA-256 hashes for the provided and expected
			// usernames and passwords.
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
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
				next.ServeHTTP(w, r)
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

func mongoTlsConfig(caFile string, certFile string, keyFile string) *tls.Config {
	caCertPool := x509.NewCertPool()
	if strings.Compare(caFile, "") == 0 || strings.Compare(certFile, "") == 0 || strings.Compare(keyFile, "") == 0 {
		return nil
	}
	// Loads CA certificate file
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Error(`Unable to load caCert`, zap.Error(err), zap.String("caFile", caFile))
		return nil
	}
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Error("Error: CA file must be in PEM format")
		return nil
	}
	// Loads client certificate files
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Error(`Unable to load client certificate files`,
			zap.Error(err),
			zap.String("certFile", certFile),
			zap.String("keyFile", keyFile),
		)
		return nil
	}
	// Instantiates a Config instance
	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
}

func findInDir(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
