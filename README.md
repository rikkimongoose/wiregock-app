# wiregock
Small and very fast and stable implementation of Wiremock with Goland and MongoDB based of fiber lib.

## Configuration

| config file  | env     | default  |  description |
|---|---|---|---|
|              | CONFIG | config.yml | path to configuration file (supports YAML, JSON and TOML) |
| server.host | SERVER_HOST | localhost | server host  |
| server.host | SERVER_POST | 8080   server port |
| mongo.url | MONGO_URL | mongodb://localhost:27017 | MongoDB connection string |
| mongo.db | MONGO_DB | local | MongoDB database name |
| mongo.collection | MONGO_COLLECTION | mocks | MongoDB collection |
| mongo.caFile | MONGO_CA |   | path to CA certificate |
| mongo.certFile | MONGO_CERT |   | path to public client certificate |
| mongo.keyFile | MONGO_KEY |   | path to private client key |
| log.encoding | LOG_ENCODING | json | storage format for logs |
| log.output | LOG_OUTPUTPATH | stdout,/tmp/logs | output pipelines for logs |
| log.erroutput | LOG_OUTPUTERRORPATH | stderr  | error pipelines for logs |

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
* **matchesXPath** XPath matcher described above can be combined with another matcher, such that the value returned from the XPath query is evaluated against it: