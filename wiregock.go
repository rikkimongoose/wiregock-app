package main

import (
    "fmt"
    "flag"
    "github.com/ilyakaznacheev/cleanenv"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    //"github.com/gofiber/fiber/v3"
    //"github.com/gofiber/fiber/v3/middleware/adaptor"
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/healthcheck"
    //"github.com/gofiber/fiber/v2/middleware/adaptor"
    //"context"
    //"crypto/tls"
    //"crypto/x509"
    "os"
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    //actuator "github.com/sinhashubham95/go-actuator"
    "github.com/rikkimongoose/wiregock"
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
        Collection string `json:"collection,omitempty" yaml:"collection,omitempty" env:"MONGO_COLLECTION" env-default:"mock" env-description:"MongoDB collection"`
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

type MongoTlsConfigInput struct {
    caFile, certFile, keyFile string
}

var log *zap.Logger
var config AppConfig

func main() {

    var err error
    cfgPath := *flag.String("CONFIG", "config.yml", "Path to application config file")
    fmt.Printf(`cfgPath: %s\n\n`, cfgPath)
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
    server := fiber.New()
    installAddons(server)
    _ = loadFromMongo()
    /*for mockData := range mockDataItems {
        installWiremock(&server, &mockData)
    }*/
    serverPath := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
    log.Info("Establishing server at URL", zap.String("url", serverPath))
    //server.Listen(serverPath)
}

func loadFromMongo() []wiregock.MockData {
    ctx := context.TODO()
    opts := options.Client().ApplyURI(config.Mongo.Url)
    /*            .SetTLSConfig(mongoTlsConfig(
                        &MongoTlsConfigInput{
                            caFile: config.Mongo.caFile,
                            certFile: config.Mongo.certFile,
                            keyFile: config.Mongo.keyFile
                        }
                    )
                )*/
    client, err := mongo.Connect(ctx, opts)
    if err != nil {
        log.Error(`Database connection error`, zap.Error(err), zap.String("db", config.Mongo.Url))
        return []wiregock.MockData{}
    }

    var resultPing bson.M
    if err := client.Database(config.Mongo.Database).RunCommand(ctx, bson.D{{"ping", 1}}).Decode(&resultPing); err != nil {
        log.Error(`Database ping error`, zap.Error(err), zap.String("db", config.Mongo.Database))
        return []wiregock.MockData{}
    }
    log.Error("Pinged your deployment. You successfully connected to MongoDB!")
    var mockData []wiregock.MockData
    wiremockCollection := client.Database(config.Mongo.Database).Collection(config.Mongo.Collection)
    cursor, err := wiremockCollection.Find(ctx, bson.M{})
    if err != nil {
        log.Error(`Database cursor creation error`,
            zap.Error(err),
            zap.String("db", config.Mongo.Url),
            zap.String("collection", config.Mongo.Collection))
        return []wiregock.MockData{}
    }
    for cursor.Next(ctx) {
        var mock wiregock.MockData
        if err = cursor.Decode(&mock); err != nil {
            log.Error(`Unable to parse MockData`,
            zap.Error(err))
            continue
        }
        log.Info(`Rule loaded`)
        mockData = append(mockData, mock)
    }
    return mockData
}

func installAddons(server *fiber.App) {
    /*actuatorConfig := &actuator.Config{
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
    server.Get("/actuator", adaptor.HTTPHandlerFunc(actuator.GetActuatorHandler(actuatorConfig*/
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

/**func mongoTlsConfig(input *MongoTlsConfigInput) *tls.Config {
    caCertPool := x509.NewCertPool()
    if strings.Compare(input.caFile, "") == 0 || strings.Compare(input.certFile, "") == 0 || strings.Compare(input.keyFile, "") == 0 {
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
}**/