package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

func TestUnmarshaling(t *testing.T) {
	body := []byte(`
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
        "multipartPatterns": [
            {
                "matchingType": "ANY",
                "headers": {
                    "Content-Disposition": {
                        "contains": "name=\"info\""
                    },
                    "Content-Type": {
                        "contains": "charset"
                    }
                },
                "bodyPatterns": [
                    {
                        "equalToJson": "{}"
                    }
                ]
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
}`)

	var mockData MockData
	require.NoError(t, json.Unmarshal(body, &mockData), "Error parsing JSON format")

	require.Equal(t, "/everything", *mockData.Request.UrlPath)
	require.Equal(t, "ANY", *mockData.Request.Method)
	require.Equal(t, "xml", *mockData.Request.Headers["Accept"].Contains)
	require.Equal(t, "WireMock", *mockData.Request.QueryParameters["search_term"].EqualTo)
	require.Equal(t, ".*12345.*", *mockData.Request.Cookies["session"].Matches)
	require.Equal(t, "<search-results />", *mockData.Request.BodyPatterns[0].EqualToXml)
	require.Equal(t, "//search-results", mockData.Request.BodyPatterns[1].MatchesXPath.Expression)
	require.Equal(t, "jeff@example.com", *mockData.Request.BasicAuthCredentials.Username)
	require.Equal(t, "jeffteenjefftyjeff", *mockData.Request.BasicAuthCredentials.Password)
}

func TestAndCondition(t *testing.T) {
	tests := []struct {
		name string
		cond AndCondition
		want bool
	}{
		{
			"True", AndCondition{[]Condition{
				&DataCondition{blockRule: &BlockRule{rulesAnd: []Rule{&TrueRule{}}}},
			}}, true,
		},
		{
			"TrueTrue", AndCondition{[]Condition{
				&DataCondition{blockRule: &BlockRule{rulesAnd: []Rule{&TrueRule{}, &TrueRule{}}}},
			}}, true,
		},
		{
			"TrueFalse", AndCondition{[]Condition{
				&DataCondition{blockRule: &BlockRule{rulesAnd: []Rule{&TrueRule{}, &FalseRule{}}}},
			}}, false,
		},
		{
			"TrueFalseOr", AndCondition{[]Condition{
				&DataCondition{blockRule: &BlockRule{rulesOr: []Rule{&TrueRule{}, &FalseRule{}}}},
			}}, true,
		},
		{
			"TrueTrueOr", AndCondition{[]Condition{
				&DataCondition{blockRule: &BlockRule{rulesOr: []Rule{&TrueRule{}, &TrueRule{}}}},
			}}, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := tt.cond.Check()
			require.NoError(t, err)
			require.Equal(t, tt.want, res)
		})
	}
}

func TestUnmarshalingXPathFilter(t *testing.T) {
	body := []byte(`
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
        "bodyPatterns": [
            {
                "equalToXml": "<search-results />"
            },
            {
                "matchesXPath": {
                    "expression": "//search-results",
                    "contains": "wash",
                    "equalToXml": "<todo-item>Do the washing</todo-item>",
                    "xPathNamespaces" : {
                        "stuff" : "http://stuff.example.com",
                        "more"  : "http://more.example.com"
                    },
                    "and": [
                        {
                            "before": "2022-01-01T00:00:00"
                        },
                        {
                            "after": "2020-01-01T00:00:00"
                        }
                    ]
                }
                
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
}`)

	var mockData MockData
	require.NoError(t, json.Unmarshal(body, &mockData))

	xpath := mockData.Request.BodyPatterns[1].MatchesXPath
	require.Equal(t, "//search-results", xpath.Expression)
	require.Equal(t, "wash", *xpath.Contains)
	require.Equal(t, "<todo-item>Do the washing</todo-item>", *xpath.EqualToXml)
	require.Nil(t, xpath.EqualToJson)
	require.NotNil(t, xpath.XPathNamespaces)
}

func TestUnmarshalingBsonXPathFilter(t *testing.T) {
	source := map[string]string{"foo": "boo"}
	bin, err := bson.Marshal(source)
	require.NoError(t, err, "Binary marshaling error")

	var restored map[string]string
	require.NoError(t, bson.Unmarshal(bin, &restored), "BSON unmarshaling error")
	require.Equal(t, source, restored)
}
