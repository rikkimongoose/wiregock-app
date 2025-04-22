package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"

	"github.com/rikkimongoose/wiregock"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type MongoTlsConfig struct {
	caFile   string
	certFile string
	keyFile  string
}

type MongoMocksLoader struct {
	config *MongoConfig
	log    *zap.Logger
}

func (loader MongoMocksLoader) mongoTlsConfig(mongoTlsConfig MongoTlsConfig) *tls.Config {
	caCertPool := x509.NewCertPool()
	requiredParams := []string{mongoTlsConfig.caFile, mongoTlsConfig.certFile, mongoTlsConfig.keyFile}
	for _, param := range requiredParams {
		if strings.Compare(param, "") == 0 {
			return nil
		}
	}
	// Loads CA certificate file
	caCert, err := os.ReadFile(mongoTlsConfig.caFile)
	if err != nil {
		loader.log.Error(`Unable to load caCert`, zap.Error(err), zap.String("caFile", mongoTlsConfig.caFile))
		return nil
	}
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		loader.log.Error("Error: CA file must be in PEM format")
		return nil
	}
	// Loads client certificate files
	cert, err := tls.LoadX509KeyPair(mongoTlsConfig.certFile, mongoTlsConfig.keyFile)
	if err != nil {
		loader.log.Error(`Unable to load client certificate files`,
			zap.Error(err),
			zap.String("certFile", mongoTlsConfig.certFile),
			zap.String("keyFile", mongoTlsConfig.keyFile),
		)
		return nil
	}
	// Instantiates a Config instance
	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
}

func (loader MongoMocksLoader) Load() []MockRoute {
	var mockRoutes []MockRoute
	if loader.config == nil {
		return mockRoutes
	}
	ctx := context.TODO()
	opts := options.Client().ApplyURI(loader.config.Url)
	tlsConfig := loader.mongoTlsConfig(MongoTlsConfig{loader.config.CaFile, loader.config.CertFile, loader.config.KeyFile})
	if tlsConfig != nil {
		opts = opts.SetTLSConfig(tlsConfig)
	}

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		loader.log.Error(`Database connection error`, zap.Error(err), zap.String("db", loader.config.Url))
		return mockRoutes
	}

	var resultPing bson.M
	if err := client.Database(loader.config.Database).RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Decode(&resultPing); err != nil {
		loader.log.Error(`Database ping error`, zap.Error(err), zap.String("db", loader.config.Database))
		return mockRoutes
	}

	loader.log.Info("Pinged your deployment. You successfully connected to MongoDB!")

	for _, storage := range loader.config.Collection {
		mockRoute := loader.convertToMockRoute(MongoMockRoute{loader.config.Database, client, &ctx, storage})
		if mockRoute != nil {
			mockRoutes = append(mockRoutes, *mockRoute)
		}
	}

	return mockRoutes
}

type MongoMockRoute struct {
	db         string
	client     *mongo.Client
	ctx        *context.Context
	mockSource string
}

func (loader MongoMocksLoader) convertToMockRoute(mongoMockRoute MongoMockRoute) *MockRoute {
	var mocks []wiregock.MockData
	wiregockCollection := mongoMockRoute.client.Database(mongoMockRoute.db).Collection(mongoMockRoute.mockSource)
	cursor, err := wiregockCollection.Find(*mongoMockRoute.ctx, bson.M{})
	if err != nil {
		loader.log.Error(`Database cursor creation error`,
			zap.Error(err),
			zap.String("db", mongoMockRoute.db),
			zap.String("collection", mongoMockRoute.mockSource))
		return nil
	}
	for cursor.Next(*mongoMockRoute.ctx) {
		var mock wiregock.MockData
		if err = cursor.Decode(&mock); err != nil {
			loader.log.Error(`Unable to parse MockData`, zap.Error(err))
			continue
		}
		if mock.Request.UrlPath != nil {
			loader.log.Info(`Rule loaded`, zap.String("url", *mock.Request.UrlPath))
		} else if mock.Request.UrlPattern != nil {
			loader.log.Info(`Rule loaded`, zap.String("url regex", *mock.Request.UrlPattern))
		} else {
			loader.log.Info(`Rule loaded, but no URL to attach`)
		}
		mocks = append(mocks, mock)
	}
	return &MockRoute{mocks}
}
