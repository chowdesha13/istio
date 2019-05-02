// Copyright 2019 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated file. DO NOT EDIT.

// Package kgsearch provides access to the Knowledge Graph Search API.
//
// For product documentation, see: https://developers.google.com/knowledge-graph/
//
// Creating a client
//
// Usage example:
//
//   import "google.golang.org/api/kgsearch/v1"
//   ...
//   ctx := context.Background()
//   kgsearchService, err := kgsearch.NewService(ctx)
//
// In this example, Google Application Default Credentials are used for authentication.
//
// For information on how to create and obtain Application Default Credentials, see https://developers.google.com/identity/protocols/application-default-credentials.
//
// Other authentication options
//
// To use an API key for authentication (note: some APIs do not support API keys), use option.WithAPIKey:
//
//   kgsearchService, err := kgsearch.NewService(ctx, option.WithAPIKey("AIza..."))
//
// To use an OAuth token (e.g., a user token obtained via a three-legged OAuth flow), use option.WithTokenSource:
//
//   config := &oauth2.Config{...}
//   // ...
//   token, err := config.Exchange(ctx, ...)
//   kgsearchService, err := kgsearch.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
//
// See https://godoc.org/google.golang.org/api/option/ for details on options.
package kgsearch // import "google.golang.org/api/kgsearch/v1"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gensupport "google.golang.org/api/gensupport"
	googleapi "google.golang.org/api/googleapi"
	option "google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = gensupport.MarshalJSON
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace
var _ = context.Canceled

const apiId = "kgsearch:v1"
const apiName = "kgsearch"
const apiVersion = "v1"
const basePath = "https://kgsearch.googleapis.com/"

// NewService creates a new Service.
func NewService(ctx context.Context, opts ...option.ClientOption) (*Service, error) {
	client, endpoint, err := htransport.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	s, err := New(client)
	if err != nil {
		return nil, err
	}
	if endpoint != "" {
		s.BasePath = endpoint
	}
	return s, nil
}

// New creates a new Service. It uses the provided http.Client for requests.
//
// Deprecated: please use NewService instead.
// To provide a custom HTTP client, use option.WithHTTPClient.
// If you are using google.golang.org/api/googleapis/transport.APIKey, use option.WithAPIKey with NewService instead.
func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Entities = NewEntitiesService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Entities *EntitiesService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewEntitiesService(s *Service) *EntitiesService {
	rs := &EntitiesService{s: s}
	return rs
}

type EntitiesService struct {
	s *Service
}

// SearchResponse: Response message includes the context and a list of
// matching results
// which contain the detail of associated entities.
type SearchResponse struct {

	// ItemListElement: The item list of search results.
	ItemListElement []interface{} `json:"itemListElement,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ItemListElement") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "ItemListElement") to
	// include in API requests with the JSON null value. By default, fields
	// with empty values are omitted from API requests. However, any field
	// with an empty value appearing in NullFields will be sent to the
	// server as null. It is an error if a field in this list has a
	// non-empty value. This may be used to include null fields in Patch
	// requests.
	NullFields []string `json:"-"`
}

func (s *SearchResponse) MarshalJSON() ([]byte, error) {
	type NoMethod SearchResponse
	raw := NoMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// method id "kgsearch.entities.search":

type EntitiesSearchCall struct {
	s            *Service
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// Search: Searches Knowledge Graph for entities that match the
// constraints.
// A list of matched entities will be returned in response, which will
// be in
// JSON-LD format and compatible with http://schema.org
func (r *EntitiesService) Search() *EntitiesSearchCall {
	c := &EntitiesSearchCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	return c
}

// Ids sets the optional parameter "ids": The list of entity id to be
// used for search instead of query string.
// To specify multiple ids in the HTTP request, repeat the parameter in
// the
// URL as in ...?ids=A&ids=B
func (c *EntitiesSearchCall) Ids(ids ...string) *EntitiesSearchCall {
	c.urlParams_.SetMulti("ids", append([]string{}, ids...))
	return c
}

// Indent sets the optional parameter "indent": Enables indenting of
// json results.
func (c *EntitiesSearchCall) Indent(indent bool) *EntitiesSearchCall {
	c.urlParams_.Set("indent", fmt.Sprint(indent))
	return c
}

// Languages sets the optional parameter "languages": The list of
// language codes (defined in ISO 693) to run the query with,
// e.g. 'en'.
func (c *EntitiesSearchCall) Languages(languages ...string) *EntitiesSearchCall {
	c.urlParams_.SetMulti("languages", append([]string{}, languages...))
	return c
}

// Limit sets the optional parameter "limit": Limits the number of
// entities to be returned.
func (c *EntitiesSearchCall) Limit(limit int64) *EntitiesSearchCall {
	c.urlParams_.Set("limit", fmt.Sprint(limit))
	return c
}

// Prefix sets the optional parameter "prefix": Enables prefix match
// against names and aliases of entities
func (c *EntitiesSearchCall) Prefix(prefix bool) *EntitiesSearchCall {
	c.urlParams_.Set("prefix", fmt.Sprint(prefix))
	return c
}

// Query sets the optional parameter "query": The literal query string
// for search.
func (c *EntitiesSearchCall) Query(query string) *EntitiesSearchCall {
	c.urlParams_.Set("query", query)
	return c
}

// Types sets the optional parameter "types": Restricts returned
// entities with these types, e.g. Person
// (as defined in http://schema.org/Person). If multiple types are
// specified,
// returned entities will contain one or more of these types.
func (c *EntitiesSearchCall) Types(types ...string) *EntitiesSearchCall {
	c.urlParams_.SetMulti("types", append([]string{}, types...))
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EntitiesSearchCall) Fields(s ...googleapi.Field) *EntitiesSearchCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *EntitiesSearchCall) IfNoneMatch(entityTag string) *EntitiesSearchCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *EntitiesSearchCall) Context(ctx context.Context) *EntitiesSearchCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *EntitiesSearchCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *EntitiesSearchCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	c.urlParams_.Set("prettyPrint", "false")
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/entities:search")
	urls += "?" + c.urlParams_.Encode()
	req, err := http.NewRequest("GET", urls, body)
	if err != nil {
		return nil, err
	}
	req.Header = reqHeaders
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "kgsearch.entities.search" call.
// Exactly one of *SearchResponse or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *SearchResponse.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *EntitiesSearchCall) Do(opts ...googleapi.CallOption) (*SearchResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := gensupport.DecodeResponse(target, res); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches Knowledge Graph for entities that match the constraints.\nA list of matched entities will be returned in response, which will be in\nJSON-LD format and compatible with http://schema.org",
	//   "flatPath": "v1/entities:search",
	//   "httpMethod": "GET",
	//   "id": "kgsearch.entities.search",
	//   "parameterOrder": [],
	//   "parameters": {
	//     "ids": {
	//       "description": "The list of entity id to be used for search instead of query string.\nTo specify multiple ids in the HTTP request, repeat the parameter in the\nURL as in ...?ids=A\u0026ids=B",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "indent": {
	//       "description": "Enables indenting of json results.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "languages": {
	//       "description": "The list of language codes (defined in ISO 693) to run the query with,\ne.g. 'en'.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "limit": {
	//       "description": "Limits the number of entities to be returned.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "prefix": {
	//       "description": "Enables prefix match against names and aliases of entities",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "query": {
	//       "description": "The literal query string for search.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "types": {
	//       "description": "Restricts returned entities with these types, e.g. Person\n(as defined in http://schema.org/Person). If multiple types are specified,\nreturned entities will contain one or more of these types.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/entities:search",
	//   "response": {
	//     "$ref": "SearchResponse"
	//   }
	// }

}
