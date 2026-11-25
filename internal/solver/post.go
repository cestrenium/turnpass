package solver

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cestrenium/turnpass/internal/challenge"
	"github.com/cestrenium/turnpass/internal/codec"
	tperr "github.com/cestrenium/turnpass/internal/errors"
	"github.com/cestrenium/turnpass/internal/transport"
)

// Stage names the payload stage for a challenge POST.
type Stage string

const (
	StageInitial      Stage = "initial"
	StageProbes       Stage = "probes"
	StageInteraction  Stage = "interaction"
	StageOrchestrator Stage = "orchestrator"
	StageClearance    Stage = "clearance"
)

// PostResult holds the result of a challenge POST: the decoded VM program
// bytecode and the time it arrived.
type PostResult struct {
	// Program is the decoded VM program's bytecode (base64-decoded after
	// mask removal).
	Program []byte
	// ReceivedMs is when the response was fully read, in epoch milliseconds.
	ReceivedMs int64
	// Status is the HTTP status code of the response.
	Status int
	// Body is the raw response body (before decoding).
	Body []byte
}

// PostChallenge sends an encoded challenge payload to the POST URL and decodes
// the response. The request includes the cf-chl header, origin, and referer
// matching cfsolve's http::requests::post_orchestrator format.
//
// The response is decoded using codec.DecodeResponse with the ray token from
// the initial request, then base64-decoded to get the VM program bytecode.
//
// This mirrors cfsolve's session::channel::Channel::post function.
func PostChallenge(ctx context.Context, client *transport.BrowserClient, initReq *challenge.InitialRequest, iframeURL, encodedBody string, stage Stage, sink Sink) (*PostResult, error) {
	sink.Progress(fmt.Sprintf("[%s] POSTing %d bytes to %s", stage, len(encodedBody), initReq.URL))

	// Parse the POST URL to get the origin.
	postURL, _ := url.Parse(initReq.URL)
	origin := ""
	if postURL != nil {
		origin = postURL.Scheme + "://" + postURL.Host
	}

	// Use "orchestrator_post" kind for orchestrator POSTs, "challenge_post"
	// for iframe POSTs. The kind selects the header template from the profile.
	// The profile template provides static headers (accept, content-type,
	// sec-fetch-*, accept-language, priority, accept-encoding, cf-chl-ra)
	// and dynamic header slots (origin, cf-chl, content-length, referer,
	// user-agent) that we fill in here.
	kind := "challenge_post"
	if stage == StageOrchestrator {
		kind = "orchestrator_post"
	}

	// Dynamic headers that the template expects us to fill in.
	headers := map[string]string{
		"cf-chl":  initReq.CfChl,
		"origin":  origin,
		"referer": iframeURL,
	}

	resp, err := client.Do(ctx, kind, http.MethodPost, initReq.URL,
		stringReader(encodedBody),
		headers,
	)
	if err != nil {
		return nil, tperr.NewNetwork(fmt.Errorf("[%s] POST failed: %w", stage, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, tperr.NewNetwork(fmt.Errorf("[%s] reading response body: %w", stage, err))
	}

	sink.Progress(fmt.Sprintf("[%s] POST returned HTTP %d; %d bytes", stage, resp.StatusCode, len(body)))

	result := &PostResult{
		Status: resp.StatusCode,
		Body:   body,
	}

	if resp.StatusCode != 200 {
		sink.Artifact(string(stage)+"-response.bin", body)
		return result, tperr.NewRejected(tperr.Stage(stage), fmt.Errorf("[%s] POST returned HTTP %d; response saved", stage, resp.StatusCode))
	}

	// Decode the response: remove the XOR mask using the ray token.
	if initReq.Ray == "" {
		return result, tperr.NewUnsupported(fmt.Errorf("[%s] no ray token for response decoding", stage))
	}

	decoded, err := codec.DecodeResponse(body, initReq.Ray)
	if err != nil {
		sink.Artifact(string(stage)+"-response.bin", body)
		return result, tperr.NewUnsupported(fmt.Errorf("[%s] decoding response: %w", stage, err))
	}

	sink.Artifact(string(stage)+"-response.decoded.txt", decoded)

	// The decoded text is base64-encoded VM bytecode.
	program, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return result, tperr.NewUnsupported(fmt.Errorf("[%s] base64-decoding VM program: %w", stage, err))
	}

	sink.Progress(fmt.Sprintf("[%s] decoded VM program: %d bytes", stage, len(program)))
	result.Program = program

	return result, nil
}

// stringReader returns an io.Reader that reads from s.
func stringReader(s string) io.Reader {
	return &stringReaderImpl{s: s}
}

type stringReaderImpl struct {
	s   string
	pos int
}

func (r *stringReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}
