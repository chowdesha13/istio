// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// IsJwtExpired checks if the JWT token is expired compared with the given time, without validating it.
func IsJwtExpired(token string, now time.Time) (bool, error) {
	claims, err := parseJwtClaims(token)
	if err != nil {
		return true, err
	}

	var expiration time.Time
	if claims["exp"] == nil {
		// The JWT doesn't have "exp", so it's always valid. E.g., the K8s first party JWT.
		return false, nil
	}
	switch exp := claims["exp"].(type) {
	case float64:
		expiration = time.Unix(int64(exp), 0)
	case json.Number:
		v, _ := exp.Int64()
		expiration = time.Unix(v, 0)
	}
	if now.After(expiration) {
		return true, nil
	}
	return false, nil

}

// GetAud returns the claim `aud` from the token. Returns nil if not found.
func GetAud(token string) ([]string, error) {
	claims, err := parseJwtClaims(token)
	if err != nil {
		return nil, err
	}

	rawAud := claims["aud"]
	if rawAud == nil {
		return nil, fmt.Errorf("no aud in the token claims")
	}

	data, err := json.Marshal(rawAud)
	if err != nil {
		return nil, err
	}

	var singleAud string
	if err = json.Unmarshal(data, &singleAud); err == nil {
		return []string{singleAud}, nil
	}

	var listAud []string
	if err = json.Unmarshal(data, &listAud); err == nil {
		return listAud, nil
	}

	return nil, err
}

type jwtPayload struct {
	// Aud is JWT token audience - used to identify 3p tokens.
	// It is empty for the default K8S tokens.
	Aud []string `json:"aud"`
}

// IsK8SUnbound detects if the token is a K8S unbound token.
// It is a regular JWT with no audience and expiration, which can
// be exchanged with bound tokens with audience.
//
// This is used to determine if we check audience in the token.
// Clients should not use unbound tokens except in cases where
// bound tokens are not possible.
func IsK8SUnbound(jwt string) bool {
	jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) != 3 {
		return false // unbound tokens are valid JWT
	}
	payload := jwtSplit[1]

	payloadBytes, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return false // unbound tokens are valid JWT
	}

	structuredPayload := &jwtPayload{}
	err = json.Unmarshal(payloadBytes, &structuredPayload)
	if err != nil {
		return false
	}

	return len(structuredPayload.Aud) == 0
}

func parseJwtClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token contains an invalid number of segments: %d, expected: 3", len(parts))
	}

	// Decode the second part.
	claimBytes, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))

	claims := make(map[string]interface{})
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode the JWT claims")
	}
	return claims, nil
}

func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
