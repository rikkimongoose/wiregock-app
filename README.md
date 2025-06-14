# wiregock
<img src="wiregock-logo.png" alt="Логотип" height="100">

Small and very fast and stable implementation of [Wiremock](https://wiremock.org/docs/request-matching/) with Golang and JSON configs (MongoDB is supported as well) based on Gorilla MUX lib. It simulates APIs that doesn't exist yet, implementing the core subdivision of WireMock DSL. You can just easily move your WireMock configs to MongoDB, use this config for wiregock and enjoy your mock HTTP server.

Original WireMock, being implemented on Java, is kinda huge and complicated for ordinary testers. Golang, being compiled language, is just [faster](https://www.youtube.com/watch?v=8CiErLxdaA8).

## Configuration

| config file  | env     | default  |  description |
|---|---|---|---|
|              | CONFIG | config.yml | path to configuration file (supports YAML, JSON and TOML) |
| server.host | SERVER_HOST | localhost | server host  |
| server.port | SERVER_PORT | 8080  | server port |
| server.multipartBuffSizeBytes | MULTIPART_BUFF_SIZE | 0x2000000 | max multipart file size allowed |
| server.writeTimeoutSec | WRITE_TIMEOUT_SEC | 15 | max duration before timing out writes of the response |
| server.readTimeoutSec | READ_TIMEOUT_SEC | 15 | max duration for reading the entire request |
| server.https | SERVER_HTTPS | false | start server in HTTPS mode |
| server.portHttps | SERVER_PORT_HTTPS | false | server port in HTTPS mode |
| server.certFile | HTTPS_CERT |  | path to public client certificate |
| server.keyFile | HTTPS_KEY |  | path to private client key |
| mongo.url | MONGO_URL | mongodb://localhost:27017 | MongoDB connection string |
| mongo.db | MONGO_DB | local | MongoDB database name |
| mongo.collection | MONGO_COLLECTION | mocks | MongoDB collection of mocks |
| mongo.caFile | MONGO_CA |   | path to CA certificate |
| mongo.certFile | MONGO_CERT |   | path to public client certificate |
| mongo.keyFile | MONGO_KEY |   | path to private client key |
| filesource.mockfiles | MOCKFILES_COLLECTION |   | JSON file with mocks |
| filesource.dir | MOCKFILES_DIR | ./  | Directory with mock files |
| filesource.mask | MOCKFILES_MASK | *.json | Mask for mock files |
| filesource.autoUpdate | MOCKFILES_AUTOUPDATE | true | Update when a mock file changed without restarting the application |
| log.level | LOG_LEVEL | Info | storage format for logs |
| log.encoding | LOG_ENCODING | json | storage format for logs: Debug, Info, Warn, Error, DPanic, Panic, Fatal |
| log.output | LOG_OUTPUTPATH | stdout,/tmp/logs | output pipelines for logs |
| log.erroutput | LOG_OUTPUTERRORPATH | stderr  | error pipelines for logs |

## Configuration mock route file example
```json
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
```
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

* **urlPath**, **url** equality matching on path and query 
* **urlPattern** regex matching on path and query
* **method** HTTP method. To accept all, use **ANY**
* **headers**
* **queryParameters**
* **cookies**
* **bodyPatterns**
* **basicAuthCredentials**
* **matchingType** accept only **ALL** (default) params or **ANY** of params

### Comparation

* **equalTo** exact equality
* **binaryEqualTo** Unlike the above equalTo operator, this compares byte arrays (or their equivalent base64 representation).
* **contains** string contains the value
* **matches** compare by RegExp
* **wildcards** compare with wildcards (**\***, **?**)
* **equalToJson** if the attribute (most likely the request body in practice) is valid JSON and is a semantic match for the expected value.
* **equalToXml** if the attribute value is valid XML and is semantically equal to the expected XML document
* **matchesXPath** XPath matcher for XML objects.
* **ignoreArrayOrder** ignore order of array items
* **ignoreExtraElements** ignore extra elements of array items
* **matchesJsonPath** check by Json Path
* **matchesJsonSchema** check by Json Schema
* **includes** possible elements
* **hasExactly** exact elements 

### Response

* **status**
* **body**
* **bodyFileName**
* **headers**
* **cookies**

### Templates

Templates are based on [mustache](https://mustache.github.io/) engine. There's support of default variable *request* based on request data.

* **request.id** - The unique ID of each request
* **request.url** - URL path and query
* **#request.queryFull.\<key>** - values of a query parameter (zero indexed) e.g. *{{#request.queryFull.search}}{{.}}{{/request.queryFull.search}}*
* **request.query.\<key>** - First value of a query parameter e.g. *request.query.search*
* **request.method** - request method e.g. *POST*
* **request.host** - hostname part of the URL e.g. *my.example.com*
* **request.port** - port number e.g. *8080*
* **request.scheme** - protocol part of the URL e.g. *https*
* **request.baseUrl** - URL up to the start of the path e.g. *https://my.example.com:8080*
* **request.headersFull.<key>** - values of a header (zero indexed) e.g. *{{#request.headers.ManyThings}}{{.}}{{/request.headers.ManyThings}}*
* **request.headers.<key>** - first value of a request header e.g. *request.headers.X-Request-Id*
* **request.cookies.<key>** - First value of a request cookie e.g. *request.cookies.JSESSIONID*
* **request.body** - Request body text (avoid for non-text bodies)
* **request.bodyAsBase64** - The Base64 representation of the request body.

## Changelog
### v1.2.2
* some bugfixes in JsonPath Rule
* append more unit test
* move library to app source code

### v1.2.0
* add support for HTTPS server 
* add support for hot reload of mock files

### v1.0.0
* refactoring
* **matchesJsonPath** JSON path implemented
* **matchesJsonSchema** JSON schema matcher implemented
* **xmlPath** and **jsonPath** helpers are implemented
* **request.parts** template for multipart files is implemented

### v0.10.6

* add templates support
* add JsonPath and JsonSchema support

### v0.10.4

* add base templates support

### v0.10.0

* add **equalToJson**, **equalToXml**, **matchesXPath** support
* add multipart files support

### v0.9.2

* some refactoring

### v0.9.0

* add support of loading mocks from files by directory

### v0.8.8

* add support of mock route data in JSON files

### v0.8.6

* add */mock* route
* add */healthcheck* route

### v0.8.4

* add *mockfiles* property and loading mocks from files
* add *log.level* property

### v0.8.2

Initial version. Just basic functionality
