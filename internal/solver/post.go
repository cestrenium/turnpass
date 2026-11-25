package solver

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

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
// the response. The request includes the cf-chl header and the iframe's
// origin as the Referer.
//
// The response is decoded using codec.DecodeResponse with the ray token from
// the initial request, then base64-decoded to get the VM program bytecode.
//
// This mirrors cfsolve's session::channel::Channel::post function.
func PostChallenge(ctx context.Context, client *transport.BrowserClient, initReq *challenge.InitialRequest, iframeURL, encodedBody string, stage Stage, sink Sink) (*PostResult, error) {
	sink.Progress(fmt.Sprintf("[%s] POSTing %d bytes to %s", stage, len(encodedBody), initReq.URL))

	// Build the POST request with the required headers.
	resp, err := client.Do(ctx, "challenge_post", http.MethodPost, initReq.URL,
		stringReader(encodedBody),
		map[string]string{
			"Content-Type": "text/plain;charset=UTF-8",
			"cf-chl":       initReq.CfChl,
			"cf-chl-ra":    "0",
		},
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
