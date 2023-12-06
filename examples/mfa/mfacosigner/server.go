package mfacosigner

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner/jwks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Server struct {
	cosigner *MfaCosigner
}

func New(serverUri, rpID, rpOrigin, RPDisplayName string) (*Server, error) {
	server := &Server{}

	mux := http.NewServeMux()

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: RPDisplayName,
		RPID:          rpID,
		RPOrigin:      rpOrigin,
	}

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	jwksServer, kid, err := jwks.NewJwksServer(signer, alg)
	if err != nil {
		return nil, err
	}

	fmt.Println("JWKS hosted at", jwksServer.URI()+"/.well-known/jwks.json")
	server.cosigner, err = NewCosigner(signer, alg, serverUri, kid, cfg)
	if err != nil {
		fmt.Println("failed to initialize cosigner: ", err)
		return nil, err
	}

	mux.Handle("/", http.FileServer(http.Dir("mfacosigner/static")))
	mux.HandleFunc("/mfa-auth-init", server.initAuth)
	mux.HandleFunc("/check-registration", server.checkIfRegistered)
	mux.HandleFunc("/register/begin", server.beginRegistration)
	mux.HandleFunc("/register/finish", server.finishRegistration)
	mux.HandleFunc("/login/begin", server.beginLogin)
	mux.HandleFunc("/login/finish", server.finishLogin)
	mux.HandleFunc("/sign", server.signPkt)

	err = http.ListenAndServe(":3003", mux) //TODO: use URI sent in constructor
	return nil, err
}

func (s *Server) URI() string {
	return s.cosigner.Issuer
}

func (s *Server) initAuth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	pktB64 := []byte(r.URL.Query().Get("pkt"))
	pktJson, err := util.Base64DecodeForJWT(pktB64)
	if err != nil {
		return
	}
	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return
	}
	sig := []byte(r.URL.Query().Get("sig1"))

	authID, err := s.cosigner.InitAuth(pkt, sig)
	if err != nil {
		http.Error(w, "Error initiating authentication", http.StatusInternalServerError)
		return
	}
	mfapage := fmt.Sprintf("/?authid=%s", authID)

	http.Redirect(w, r, mfapage, http.StatusFound)
}

func (s *Server) checkIfRegistered(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	registered := s.cosigner.CheckIsRegistered(authID)

	response, _ := json.Marshal(map[string]bool{
		"isRegistered": registered,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func GetAuthID(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return string([]byte(r.URL.Query().Get("authid"))), nil
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	options, err := s.cosigner.BeginRegistration(authID)

	optionsJson, err := json.Marshal(options)
	if err != nil {
		fmt.Printf("Failed to marshal options: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	err = s.cosigner.FinishRegistration(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(201)
	w.Write([]byte("MFA registration Successful! You may now close this window"))
	fmt.Println("MFA registration complete")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	options, err := s.cosigner.BeginLogin(authID)
	if err != nil {
		fmt.Println("Failed to begin webauthn login:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	optionsJson, err := json.Marshal(options)
	if err != nil {
		fmt.Println("Failed to marshal options:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	authcode, ruri, err := s.cosigner.FinishLogin(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mfaURI := string(ruri) + "?authcode=" + string(authcode)

	response, _ := json.Marshal(map[string]string{
		"redirect_uri": mfaURI,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func (s *Server) signPkt(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("error parsing authcode and sig:", err)
		return
	}

	authcode := []byte(r.URL.Query().Get("authcode"))
	sig := []byte(r.URL.Query().Get("sig2"))

	if pkt, err := s.cosigner.RedeemAuthcode(authcode, sig); err != nil {
		fmt.Println("Signature Grant Failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		pktJson, err := json.Marshal(pkt)
		if err != nil {
			fmt.Println("error unmarshal:", err)
			return
		}

		pktB64 := util.Base64EncodeForJWT(pktJson)
		response, _ := json.Marshal(map[string]string{
			"pkt": string(pktB64),
		})

		w.WriteHeader(201)
		w.Write(response)
	}
}
