package main

import (
    "fmt"
    "flag"
    "github.com/ilyakaznacheev/cleanenv"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"

    "context"
    "crypto/tls"
    "crypto/x509"
    "os"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "github.com/rikkimongoose/wiregock"
    "strings"
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
    mockRoutesData := loadMocksFromMongo(config.Mongo.Collection)
    if mockRoutesData == nil {
        log.Warn(`Mocks collection is empty`)
    }
    /*else {
        for _, mockRoute := range mockRoutes {
        for _, mock := mockRoute.mocks {
            installMock(&server, &mock)
        }
    }
}*/
}


func loadMocksFromMongo(storages []string) *MockRoutesData {
    ctx := context.TODO()
    tlsConfig := mongoTlsConfig(config.Mongo.CaFile, config.Mongo.CertFile, config.Mongo.KeyFile)
    opts := options.Client().ApplyURI(config.Mongo.Url)
    if tlsConfig != nil {
        opts = opts.SetTLSConfig(tlsConfig)
    }

    client, err := mongo.Connect(ctx, opts)
    if err != nil {
        log.Error(`Database connection error`, zap.Error(err), zap.String("db", config.Mongo.Url))
        return nil
    }

    var resultPing bson.M
    if err := client.Database(config.Mongo.Database).RunCommand(ctx, bson.D{{"ping", 1}}).Decode(&resultPing); err != nil {
        log.Error(`Database ping error`, zap.Error(err), zap.String("db", config.Mongo.Database))
        return nil
    }

    log.Info("Pinged your deployment. You successfully connected to MongoDB!")

    var mockRoutes []MockRoute

    for _, storage := range storages {
        mockRoute := loadMock(client, &ctx, storage)
        if mockRoute != nil {
            mockRoutes = append(mockRoutes, *mockRoute)
        }
    }
    
    return &MockRoutesData{mockRoutes}
}

func loadMock(client *mongo.Client, ctx *context.Context, mockSource string) *MockRoute {
    var mocks []wiregock.MockData
    wiremockCollection := client.Database(config.Mongo.Database).Collection(mockSource)
    cursor, err := wiremockCollection.Find(*ctx, bson.M{})
    if err != nil {
        log.Error(`Database cursor creation error`,
            zap.Error(err),
            zap.String("db", config.Mongo.Url),
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

/*func installWiremock(server *fiber.App, mock *wiremock.MockData) {
    if mock.Request == nil {
        return
    }
    request := mock.Request
    if request.Method == nil {
        return
    }
    methodNames := loadMethods(*request.Method)
    if request.BasicAuthCredentials != nil && request.BasicAuthCredentials.Username != nil && request.BasicAuthCredentials.Password != nil {
        server.Use(basicauth.New(basicauth.Config{
            Users: map[string]string{
                *request.BasicAuthCredentials.Username: *request.BasicAuthCredentials.Password
                },
            }))
    }

    url := request.UrlPath
    if url == nil {
        url = &fmt.Sprintf("regex(%s)", *request.UrlPattern)
    }

    server.Add(methodNames, *url, func(c fiber.Ctx) error {
        dc := DataContext{
            Body: func() string {
                return string(c.Body()[:])
            }
            Get: func(key string) string {
                return c.Get(key, "")
            }
            Params: func(key string) string {
                return c.Params(key, "")
            }
            Cookies: func(key string) string {
                return c.Cookies(key, "")
            }
        }
        condition := parseCondition(request, &dc)
        result, err := condition.check()
        if err != nil {
           return c.Status(fiber.StatusInternalServerError).SendString(err)
        }
        if !result {
            return c.Status(fiber.StatusNotFound)
        }

        traceId := c.Params("traceparent")
        if traceId == nil {
            c.Set("traceparent", generateTraceparent())
        } else {
            c.Set("traceparent", traceId)
        }

        if mock.Response == nil {
            return c.Status(fiber.StatusOK).SendString("")
        }

        response := mock.Response
        if response.Headers != nil {
            for key, value := range response.Headers {
                c.Set(key, value)
            }
        }

        if response.Cookies != nil {
            for key, value := range response.Cookies {
                c.Cookie(key, value)
            }
        }

        if statusCode != nil {
            c.Status(*response.Status)
        } else {
            c.Status(fiber.StatusOK)
        }
        

        body := response.Body
        if body != nil {
            return c.SendString(*body)
        }
        return nil
        
    })
}*/

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

