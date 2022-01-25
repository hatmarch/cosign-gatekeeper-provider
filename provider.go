// Copyright The Sigstore Authors.
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

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
	timeout = 30 * time.Second
)

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

	if err := http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}

func Keys(cfg map[string][]byte) []*ecdsa.PublicKey {
	keys := []*ecdsa.PublicKey{}

	pems := parsePems(cfg["cosign.pub"])
	for _, p := range pems {
		// TODO check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			panic(err)
		}
		keys = append(keys, key.(*ecdsa.PublicKey))
	}
	return keys
}


func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)

		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		fmt.Println(err)

		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)

	ctx := req.Context()
	ro := options.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("ERROR: %v", err), w)
		return
	}

	secretKeyRef := os.Getenv("SECRET_NAME")
	cfg, err := kubernetes.GetKeyPairSecret(ctx, secretKeyRef)
	if err != nil {
		fmt.Println(err)
		sendResponse(nil, "unable to get key pair secret", w)
		return
	}

	for _, k := range Keys(cfg.Data) {

		ecdsaVerifier, err := signature.LoadECDSAVerifier(k, crypto.SHA256)
		if err != nil {
			fmt.Println(err)
			sendResponse(nil, "Unable to get verifier from key", w)
			return
		}

		// iterate over all provider keys
		for _, key := range providerRequest.Request.Keys {
			fmt.Println("verify signature for:", key)
			ref, err := name.ParseReference(key)
			if err != nil {
				sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
				return
			}

			checkedSignatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosign.CheckOpts{
				RekorURL:           "https://rekor.sigstore.dev",
				RegistryClientOpts: co,
				RootCerts:          fulcio.GetRoots(),
				SigVerifier:   ecdsaVerifier,
				ClaimVerifier: cosign.SimpleClaimVerifier,
			})

			if err != nil {
				fmt.Println(err)
				sendResponse(nil, fmt.Sprintf("VerifyImageSignatures: %v", err), w)
				return
			}

			if bundleVerified {
				fmt.Println("signature verified for:", key)
				fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)
				results = append(results, externaldata.Item{
					Key:   key,
					Value: key + "_valid",
				})
			} else {
				fmt.Printf("no valid signatures found for: %s\n", key)
				results = append(results, externaldata.Item{
					Key:   key,
					Error: key + "_invalid",
				})
			}
		}
	}

	sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}
