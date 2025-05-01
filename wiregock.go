package main

import (
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const (
	productName    = "WireGock"
	productVersion = "1.2.2"
)

type ServerConfig struct {
	Host                   string `json:"host,omitempty" yaml:"host,omitempty" env:"SERVER_HOST" env-default:"localhost" env-description:"server host"`
	Port                   int    `json:"port,omitempty" yaml:"port,omitempty" env:"SERVER_PORT" env-default:"8080" env-description:"server port"`
	MultipartBuffSizeBytes int64  `json:"multipartBuffSizeBytes,omitempty" yaml:"multipartBuffSizeBytes,omitempty" env:"MULTIPART_BUFF_SIZE" env-default:"33554432" env-description:"max multipart file size allowed"`
	WriteTimeoutSec        int    `json:"writeTimeoutSec,omitempty" yaml:"writeTimeoutSec,omitempty" env:"WRITE_TIMEOUT_SEC" env-default:"15" env-description:"max duration before timing out writes of the response"`
	ReadTimeoutSec         int    `json:"readTimeoutSec,omitempty" yaml:"readTimeoutSec,omitempty" env:"READ_TIMEOUT_SEC" env-default:"15" env-description:"max duration for reading the entire request"`
	Https                  bool   `json:"https,omitempty" yaml:"https,omitempty" env:"SERVER_HTTPS" env-default:"false" env-description:"start server in HTTPS mode"`
	PortHttps              int    `json:"portHttps,omitempty" yaml:"portHttps,omitempty" env:"SERVER_PORT_HTTPS" env-default:"443" env-description:"server port in HTTPS mode"`
	CertFile               string `json:"certFile,omitempty" yaml:"certFile,omitempty" env:"HTTPS_CERT" env-default:"" env-description:"path to public client certificate"`
	KeyFile                string `json:"keyFile,omitempty" yaml:"keyFile,omitempty" env:"HTTPS_KEY" env-default:"" env-description:"path to private client key"`
}

type MongoConfig struct {
	Url        string   `json:"url,omitempty" yaml:"url,omitempty" env:"MONGO_URL" env-default:"mongodb://localhost:27017" env-description:"MongoDB connection string"`
	Database   string   `json:"db,omitempty" yaml:"db,omitempty" env:"MONGO_DB" env-default:"local" env-description:"MongoDB database"`
	Collection []string `json:"collection,omitempty" yaml:"collection,omitempty" env:"MONGO_COLLECTION" env-default:"mock" env-description:"MongoDB collection"`
	CaFile     string   `json:"caFile,omitempty" yaml:"caFile,omitempty" env:"MONGO_CA" env-default:"" env-description:"path to CA certificate"`
	CertFile   string   `json:"certFile,omitempty" yaml:"certFile,omitempty" env:"MONGO_CERT" env-default:"" env-description:"path to public client certificate"`
	KeyFile    string   `json:"keyFile,omitempty" yaml:"keyFile,omitempty" env:"MONGO_KEY" env-default:"" env-description:"path to private client key"`
}

type FileSourceConfig struct {
	Files      []string `json:"mockfiles,omitempty" yaml:"mockfiles,omitempty" env:"MOCKFILES_COLLECTION" env-default:"" env-description:"JSON source files"`
	Dir        *string  `json:"dir,omitempty" yaml:"dir,omitempty" env-default:"./" env:"MOCKFILES_DIR" env-description:"Directory with mock files"`
	Mask       *string  `json:"mask,omitempty" yaml:"mask,omitempty" env-default:"*.json" env:"MOCKFILES_MASK" env-description:"Mask for mock files"`
	AutoUpdate bool     `json:"autoUpdate,omitempty" yaml:"autoUpdate,omitempty" env-default:"true" env:"MOCKFILES_AUTOUPDATE" env-description:"Update when a mock file changed without restarting the application"`
}

type LogConfig struct {
	Level            *string  `json:"level,omitempty" yaml:"level,omitempty" env-default:"Info" env:"LOG_LEVEL" env-description:"log output level: Debug, Info, Warn, Error, DPanic, Panic, Fatal"`
	Encoding         string   `json:"encoding,omitempty" yaml:"encoding,omitempty" env-default:"json" env:"LOG_ENCODING" env-description:"storage format for logs"`
	OutputPaths      []string `json:"output,omitempty" yaml:"output,omitempty" env-default:"stdout,/tmp/logs" env:"LOG_OUTPUTPATH" env-description:"output pipelines for logs"`
	ErrorOutputPaths []string `json:"erroutput,omitempty" yaml:"erroutput,omitempty" env-default:"stderr" env:"LOG_OUTPUTERRORPATH" env-description:"error pipelines for logs"`
}

type AppConfig struct {
	Server     ServerConfig      `json:"server,omitempty" yaml:"server,omitempty"`
	Mongo      *MongoConfig      `json:"mongo,omitempty" yaml:"mongo,omitempty"`
	FileSource *FileSourceConfig `json:"filesource,omitempty" yaml:"filesource,omitempty"`
	Log        LogConfig         `json:"log,omitempty" yaml:"log,omitempty"`
}

type MockRoutesData struct {
	MockRoutes []MockRoute `json:"mockRoutes,omitempty"`
}

type MockRoute struct {
	Mocks []MockData `json:"mocks,omitempty"`
}

type MocksLoader interface {
	Load() []MockRoute
}

func loadMockItems(mocksLoader MocksLoader) []MockData {
	mocks := []MockData{}
	for _, mockRoute := range mocksLoader.Load() {
		mocks = append(mocks, mockRoute.Mocks...)
	}
	return mocks
}

func main() {
	config := ConfigLoader()
	log := NewLogger(config.Log)

	dataLoader := IOLoader{log}

	server := CreateWiregockServer(mux.NewRouter(), config.Server, log)
	mongoMocksLoader := MongoMocksLoader{config.Mongo, log}
	fileMocksLoader := FileMocksLoader{config.FileSource, dataLoader, log}
	mocksMongo := loadMockItems(mongoMocksLoader)
	mocks := append(mocksMongo, loadMockItems(fileMocksLoader)...)

	mustacheService := MustacheService{dataLoader, log}
	handlers := []HandlerFactory{
		MocksHandler{mocks, dataLoader, mustacheService, MocksHandlerConfig{config.Server.MultipartBuffSizeBytes}, log},
		MocksInfoHandler{mocks},
		HealthcheckHandler{"OK"},
		ActuatorHandler{config.Server.Port},
	}
	for _, handler := range handlers {
		server.Install(handler)
	}

	server.Start()

	if config.FileSource == nil || config.FileSource.AutoUpdate {
		// Watch for changes in mock files
		// Create new watcher.
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Error("Unable to create watcher", zap.Error(err))
		}
		defer watcher.Close()

		// Start listening for events.
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					log.Info("Mock file changed", zap.String("file", event.Name))
					if event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Create) {
						server.Stop()
						mocks := append(mocksMongo, loadMockItems(fileMocksLoader)...)
						handlers := []HandlerFactory{
							MocksHandler{mocks, dataLoader, mustacheService, MocksHandlerConfig{config.Server.MultipartBuffSizeBytes}, log},
							MocksInfoHandler{mocks},
							HealthcheckHandler{"OK"},
							ActuatorHandler{config.Server.Port},
						}
						for _, handler := range handlers {
							server.Install(handler)
						}
						server.Start()
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Error("Unable to get watch file change", zap.Error(err))
				}
			}
		}()

		dir := "./"
		if config.FileSource != nil && config.FileSource.Dir != nil {
			dir = *config.FileSource.Dir
		}
		// Add a path.
		err = watcher.Add(dir) //config.FileSource.Mask
		if err != nil {
			log.Error("Unable to add path to watcher", zap.Error(err))
		} else {
			log.Info("Add watcher for changes in directory", zap.String("directory", dir))
		}
		// Block main goroutine forever.
		<-make(chan struct{})
	}
	defer log.Sync() // все асинхронные логи будут записаны перед выходом
}
