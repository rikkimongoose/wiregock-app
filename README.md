
# wiregock
Small and very fast and stable implementation of [Wiremock](https://wiremock.org/docs/request-matching/) with Goland and MongoDB based on Gorilla MUX lib. It simulates APIs that doesn't exist yet, implementing the core subdivision of WireMock DSL. You can just easily move your WireMock configs to MongoDB, use this config for wiregock and enjoy your mock HTTP server.

Original WireMock, being implemented on Java, is kinda huge and complicated for ordinary testers. Golang, being compiled language, is just [faster](https://www.youtube.com/watch?v=8CiErLxdaA8).

## Configuration

| config file  | env     | default  |  description |
|---|---|---|---|
|              | CONFIG | config.yml | path to configuration file (supports YAML, JSON and TOML) |
| server.host | SERVER_HOST | localhost | server host  |
| server.host | SERVER_POST | 8080   server port |
| mongo.url | MONGO_URL | mongodb://localhost:27017 | MongoDB connection string |
| mongo.db | MONGO_DB | local | MongoDB database name |
| mongo.collection | MONGO_COLLECTION | mocks | MongoDB collection of mocks |
| mongo.caFile | MONGO_CA |   | path to CA certificate |
| mongo.certFile | MONGO_CERT |   | path to public client certificate |
| mongo.keyFile | MONGO_KEY |   | path to private client key |
| log.level | LOG_LEVEL | Info | storage format for logs |
| log.encoding | LOG_ENCODING | json | storage format for logs: Debug, Info, Warn, Error, DPanic, Panic, Fatal |
| log.output | LOG_OUTPUTPATH | stdout,/tmp/logs | output pipelines for logs |
| log.erroutput | LOG_OUTPUTERRORPATH | stderr  | error pipelines for logs |
| mockfiles | MOCKFILES_COLLECTION |   | JSON file with mocks |

## Configuration mock route file example

    {
        "request": {
            "urlPath": "/everything",
            "method": "ANY",
            "headers": {
                "Accept": {
                    "contains": "xml"
                }
            },
            "queryParameters": {
                "search_term": {
                    "equalTo": "WireMock"
                }
            },
            "cookies": {
                "session": {
                    "matches": ".*12345.*"
                }
            },
            "bodyPatterns": [
                {
                    "equalToXml": "<search-results />"
                },
                {
                    "matchesXPath": "//search-results"
                }
            ],
            "basicAuthCredentials": {
                "username": "jeff@example.com",
                "password": "jeffteenjefftyjeff"
            }
        },
        "response": {
            "status": 200
        }
    }

## Special routes

* */mock* - return JSON with all loaded mocks
* */healthcheck* healthcheck URL, returns OK if server is running
* */actuator/env* get all the environment variables for the runtime where the application is running
* */actuator/info*  get the basic information for an application
* */actuator/metrics* get the runtime memory statistics for your application
* */actuator/ping* lightweight ping endpoint that can be used along with your load balancer
* */actuator/shutdown* bring the application down
* */actuator/threadDump* get the trace of all the goroutines

## Request Matching

Stub matching and verification queries can use the following request attributes:

* URL
* HTTP Method
* Query parameters
* Form parameters
* Headers
* Basic authentication (a special case of header matching)
* Cookies
* Request body
* Traceparent

Will be supported in following versions:

* Multipart files

### HTTP methods

* **ANY** all methods are accepted
* **GET**
* **HEAD**
* **OPTIONS**
* **TRACE**
* **PUT**
* **DELETE**
* **POST**
* **PATCH**
* **CONNECT**

### Request mapping

* **urlPath** equality matching on path and query 
* **urlPattern** regex matching on path and query
* **method** HTTP method. To accept all, use **ANY**
* **headers**
* **queryParameters**
* **cookies**
* **bodyPatterns**
* **basicAuthCredentials**

### Comparation

* **equalTo** exact equality
* **binaryEqualTo** Unlike the above equalTo operator, this compares byte arrays (or their equivalent base64 representation).
* **contains** string contains the value
* **matches** compare by RegExp
* **wildcards** compare with wildcards (**\***, **?**)

Will be supported in following versions:

* **equalToJson** if the attribute (most likely the request body in practice) is valid JSON and is a semantic match for the expected value.
* **equalToXml** if the attribute value is valid XML and is semantically equal to the expected XML document
* **matchesXPath** XPath matcher described above can be combined with another matcher, such that the value returned from the XPath query is evaluated against it.

## Changelog

### v0.8.8

* add support of single mock route data in JSON files

### v0.8.6

* add */mock* route
* add */healthcheck* route

### v0.8.4

* add *mockfiles* property and loading mocks from files
* add *log.level* property

### v0.8.2

Initial version. Just basic functionality