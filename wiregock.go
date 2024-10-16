package main

import (
    "fmt"
    "flag"
    "github.com/ilyakaznacheev/cleanenv"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "github.com/gofiber/fiber/v3"
    "github.com/gofiber/fiber/v3/middleware/adaptor"
    "github.com/gofiber/fiber/v3/middleware/healthcheck"
    "context"
    "crypto/tls"
    "crypto/x509"
    "os"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    actuator "github.com/sinhashubham95/go-actuator"
    "strings"
    "strconv"
    "github.com/rikkimongoose/wiremock"
)

const (
    productName = "WireGock"
    productVersion = "0.1.0"
)

type AppConfig struct {
    Server struct {
        Host string `json:"host,omitempty", yaml:"host,omitempty", env:"SERVER_HOST", env-default:"localhost", env-description:"server host"`
        Port string `json:"port,omitempty", yaml:"port,omitempty", env:"SERVER_PORT", env-default:"8080", env-description:"server port"`
    } `json:"server,omitempty", yaml:"server,omitempty"`
    Mongo struct {
        url string `json:"url,omitempty", yaml:"url,omitempty", env:"MONGO_URL", env-default:"mongodb://localhost:27017", env-description:"MongoDB connection string"`
        database string `json:"db,omitempty", yaml:"db,omitempty", env:"MONGO_DB", env-default:"local", env-description:"MongoDB database"`
        collection string `json:"collection,omitempty", yaml:"collection,omitempty", env:"MONGO_COLLECTION", env-default:"mock",  env-description:"MongoDB collection"`
        caFile string `json:"caFile,omitempty", yaml:"caFile,omitempty", env:"MONGO_CA", env-default:"", env-description:"path to CA certificate"`
        certFile string `json:"certFile,omitempty", yaml:"certFile,omitempty", env:"MONGO_CERT", env-default:"", env-description:"path to public client certificate"`
        keyFile string `json:"keyFile,omitempty", yaml:"keyFile,omitempty", env:"MONGO_KEY", env-default:"", env-description:"path to private client key"`
    } `json:"mongo,omitempty", yaml:"mongo,omitempty"`
    Log struct {
        Encoding string `json:"encoding,omitempty", yaml:"encoding,omitempty", env-default:"json", env:"LOG_ENCODING", env-description:"storage format for logs"`
        OutputPaths []string `json:"output,omitempty", yaml:"output,omitempty", env-default:"stdout,/tmp/logs", env:"LOG_OUTPUTPATH", env-description:"output pipelines for logs"`
        ErrorOutputPaths []string `json:"erroutput,omitempty", yaml:"erroutput,omitempty", env-default:"stderr", env:"LOG_OUTPUTERRORPATH", env-description:"error pipelines for logs"`
    } `json:"log,omitempty", yaml:"log,omitempty"`
}

type MongoTlsConfigInput struct {
    caFile, certFile, keyFile string
}

var logger *zap.Logger
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
        Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
        Encoding:         config.Log.Encoding,
        OutputPaths:      config.Log.OutputPaths,
        ErrorOutputPaths: config.Log.ErrorOutputPaths,
        Development:       false,
        DisableCaller:     false,
        DisableStacktrace: false,
        Sampling:          nil,
        EncoderConfig:     encoderCfg,
        InitialFields: map[string]interface{}{
            "pid": os.Getpid(),
        },
    }

    logger := zap.Must(zc.Build())
    if err != nil {
        panic(err) // Не удалось создать логгер
    }
    defer logger.Sync() // все асинхронные логи будут записаны перед выходом

    server := fiber.New()
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

    server := fiber.New()
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
    installAddons(&server)
    mockDataItems := loadFromMongo() 
    for mockData := range mockDataItems {
        installWiremock(&server, &mockData)
    }
    serverPath = fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
    logger.Info("Establishing server at URL", zap.String("url", serverPath))
    server.Listen(serverPath)
}

func loadFromMongo() wiremock.MockData[] {
    ctx := context.TODO()
    opts := options.Client()
                .ApplyURI(config.MongoDatabase.url)
                .SetTLSConfig(mongoTlsConfig(
                        &MongoTlsConfigInput(
                            caFile: config.Mongo.caFile,
                            certFile: config.Mongo.certFile,
                            keyFile: config.Mongo.keyFile
                        )
                    )
                )
    client, err := mongo.Connect(ctx, opts)
    var resultPing bson.M
    if err := client.Database(config.MongoDatabase.database).RunCommand(ctx, bson.D{{"ping", 1}}).Decode(&resultPing); err != nil {
        logger.Error(err)
    }
    logger.Info("Pinged your deployment. You successfully connected to MongoDB!")
    var mockData []wiremock.MockData
    wiremockCollection := client.Database(config.MongoDatabase.database).Collection(config.MongoDatabase.collection)
    cursor, err := wiremockCollection.Find(ctx, bson.M{})
    if err != nil {
        logger.Fatal(err)
    }
    for cursor.Next(ctx) {
        var mock wiremock.MockData
        if err = cursor.Decode(&mock); err != nil {
            logger.Fatal(err)
            continue
        }
        mockData = append(mockData, mock)
    }
    return mockData
}

func installAddons(server *fiber.App) {
    server.Get("/actuator", adaptor.HTTPHandlerFunc(actuator.GetActuatorHandler(actuatorConfig)))
    server.Use(healthcheck.New(healthcheck.Config{
        LivenessProbe: func(c *fiber.Ctx) bool {
            return true
        },
        LivenessEndpoint: "/live",
        ReadinessProbe: func(c *fiber.Ctx) bool {
            return true
        },
        ReadinessEndpoint: "/ready",
    }))
}

func installWiremock(server *fiber.App, mock *wiremock.MockData) {
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
}

func mongoTlsConfig(input *MongoTlsConfigInput) *tls.Config {
    caCertPool := x509.NewCertPool()
    if input.caFile == nil || input.certFile == nil || input.keyFile == nil {
        return &tls.Config {
            RootCAs: caCertPool,
            ClientAuth: tls.NoClientCert,
            ClientCAs: nil,
            InsecureSkipVerify: true,
            Certificates: []tls.Certificate{},
        }
    }
    caFile := input.caFile
    certFile := input.certFile
    keyFile := input.keyFile

    // Loads CA certificate file
    caCert, err := os.ReadFile(caFile)
    if err != nil {
        logger.Error(err)
    }
    if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
        logger.Error("Error: CA file must be in PEM format")
    }
    // Loads client certificate files
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        logger.Error(err)
    }
    // Instantiates a Config instance
    return &tls.Config{
        RootCAs:      caCertPool,
        Certificates: []tls.Certificate{cert},
    }
}