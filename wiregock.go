package main

import (
    "io"
    "fmt"
    "flag"
    "os"
    "strings"
    "context"
    "time"
    "net/http"
    "io/ioutil"
    "crypto/tls"
    "crypto/x509"
    "github.com/ilyakaznacheev/cleanenv"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "github.com/gorilla/mux"
    "github.com/rikkimongoose/wiregock"
    actuator "github.com/sinhashubham95/go-actuator"
)

const (
    productName = "WireGock"
    productVersion = "0.1.0"
)

type AppConfig struct {
    Server struct {
        Host string `yaml:"host,omitempty" env:"SERVER_HOST" env-default:"localhost" env-description:"server host"`
        Port int `yaml:"port,omitempty" env:"SERVER_PORT" env-default:"8080" env-description:"server port"`
    } `json:"server,omitempty" yaml:"server,omitempty"`
    Mongo struct {
        Url string `json:"url,omitempty" yaml:"url,omitempty" env:"MONGO_URL" env-default:"mongodb://localhost:27017" env-description:"MongoDB connection string"`
        Database string `json:"db,omitempty" yaml:"db,omitempty" env:"MONGO_DB" env-default:"local" env-description:"MongoDB database"`
        Collection []string `json:"collection,omitempty" yaml:"collection,omitempty" env:"MONGO_COLLECTION" env-default:"mock" env-description:"MongoDB collection"`
        CaFile string `json:"caFile,omitempty" yaml:"caFile,omitempty" env:"MONGO_CA" env-default:"" env-description:"path to CA certificate"`
        CertFile string `json:"certFile,omitempty" yaml:"certFile,omitempty" env:"MONGO_CERT", env-default:"" env-description:"path to public client certificate"`
        KeyFile string `json:"keyFile,omitempty" yaml:"keyFile,omitempty" env:"MONGO_KEY" env-default:"" env-description:"path to private client key"`
    } `json:"mongo" yaml:"mongo"`
    Log struct {
        Encoding string `json:"encoding,omitempty" yaml:"encoding,omitempty" env-default:"json", env:"LOG_ENCODING" env-description:"storage format for logs"`
        OutputPaths []string `json:"output,omitempty" yaml:"output,omitempty" env-default:"stdout,/tmp/logs" env:"LOG_OUTPUTPATH" env-description:"output pipelines for logs"`
        ErrorOutputPaths []string `json:"erroutput,omitempty" yaml:"erroutput,omitempty" env-default:"stderr" env:"LOG_OUTPUTERRORPATH" env-description:"error pipelines for logs"`
    } `json:"log,omitempty" yaml:"log,omitempty"`
}

type MockRoutesData struct {
    mockRoutes []MockRoute
}

type MockRoute struct {
    mocks []wiregock.MockData
}

var log *zap.Logger
var config AppConfig

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
        Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
        OutputPaths: config.Log.OutputPaths,
        ErrorOutputPaths: config.Log.ErrorOutputPaths,
        EncoderConfig: encoderCfg,
        Encoding:      config.Log.Encoding,
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
        Name: productName,
        Port: config.Server.Port,
        Version: productVersion,
    }
    actuatorHandler := actuator.GetActuatorHandler(actuatorConfig)
    router.PathPrefix("/actuator/").Handler(actuatorHandler)
    mockRoutesData := loadMocksFromMongo(
        config.Mongo.Url,
        config.Mongo.Database,
        config.Mongo.Collection,
        config.Mongo.CaFile,
        config.Mongo.CertFile,
        config.Mongo.KeyFile)
    for _, mockRoute := range mockRoutesData.mockRoutes {
        for _, mock := range mockRoute.mocks {
            methods := wiregock.LoadMethods(*mock.Request.Method)
            handler := generateHandler(&mock)
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
    serverAddr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
    log.Info("Starting up", zap.String("server", serverAddr))
    srv := &http.Server{
        Handler:      router,
        Addr:         serverAddr,
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }
    err = srv.ListenAndServe()
    if err != nil {
       log.Error(`Error starting server`,
            zap.Error(err),
            zap.String("host", config.Server.Host),
            zap.Int("port", config.Server.Port))
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
    if err := client.Database(config.Mongo.Database).RunCommand(ctx, bson.D{{"ping", 1}}).Decode(&resultPing); err != nil {
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

func generateHandler(mock *wiregock.MockData) http.HandlerFunc {
    return func(w http.ResponseWriter, req *http.Request) {
        dc := wiregock.DataContext{
            Body: func() string {
                b, err := ioutil.ReadAll(req.Body)
                if err != nil {
                    return ""
                }
                return string(b[:])
            },
            Get: func(key string) string {
                return req.Header.Get(key)
            },
            Params: func(key string) string {
                return req.URL.Query().Get(key)
            },
            Cookies: func(key string) string {
                cookie, err := req.Cookie(key)
                if err != nil {
                    return ""
                }
                return cookie.Value
            },
        }
        flusher, ok := w.(http.Flusher)
        if !ok {
            http.NotFound(w, req)
            return
        }
        condition, err := wiregock.ParseCondition(mock.Request, &dc)
        if err != nil {
            http.Error(w, "Wrong condition", http.StatusInternalServerError)
            return
        }
        result, err := condition.Check()
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

        statusCode := http.StatusOK
        response := mock.Response
        if response.Status != nil {
            statusCode = *response.Status
        }
        w.WriteHeader(statusCode)
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

        if statusCode != http.StatusOK {
            w.WriteHeader(statusCode)
        }
        if response.Body != nil {
            flusher.Flush()
            io.WriteString(w, *response.Body)
        }
        
    }
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