// Package reference holds the Cloudflare challenge option name constants.
//
// These are the obfuscated _hex property names that Cloudflare uses in
// _cf_chl_opt for various probe results and session parameters. They change
// with each new Cloudflare build. This file mirrors cfsolve's
// src/stage2/reference.rs and should be updated when Cloudflare ships a new
// build.
//
// The names are used by the probe answer matching logic to identify which
// _cf_chl_opt property holds each probe's result.
package reference

// Session parameter option names.
const (
	// PlatformOption is the challenge option naming the platform segment
	// of a probe's request path.
	PlatformOption = "_bf13c229f4183e5bc0863f59"
	// RayOption is the option holding the session's ray.
	RayOption = "_eed828ce4503e7f7475d133c"
	// NonceOption is the option holding the nonce the worker fetch requests.
	NonceOption = "_b05ae5510fcfc51f5ef65860"
)

// Shared result fields.
const (
	// SharedResult is used by clock and private-token probes.
	SharedResult = "_4f8eb26a0f0e8f1cde83205b"
	// ClockFallback is what the clock probe reports when its worker fails.
	ClockFallback = "_c69152d69f01e1841d56d1f8"
)

// Date probe fields.
const (
	DatesToday  = "_02fc3d87fc5fb56d0eff03c7"
	DatesOffset = "_faf306f9f99ed3dce219494d"
	DatesZone   = "_00b5777cf2b60a45d1d0b872"
)

// DOM mutation probe.
const (
	DOMMutationResult = "_b6fdb2d1104e34bd19027e67"
)

// Environment probe fields.
const (
	EnvironmentReferrer        = "_d92c36c516f3960a1720f1a3"
	EnvironmentAuditGroups     = "_97b56437f4f055c018023578"
	EnvironmentAuditValues     = "_2d1e29e89715c35b8d8e1927"
	EnvironmentAuditReduction  = "_205e69c5e2dbe2ee9c21fe98"
	EnvironmentAuditDecoded    = "_8469255e1c5cb0d4752b6929"
	EnvironmentAuditEncoded    = "_85ebe15fe783c98fe7e4bed3"
	EnvironmentAuditTouch      = "_c1ec04fca99016a50b19dc3b"
	EnvironmentAuditSecure     = "_830ebee3a538ccca14314ae3"
	EnvironmentAuditPermission = "_5db7449633ee9844a05cd4d1"
)

// IsolationProbeFailureFields are the isolation probe's results for blocked
// evaluation and cross-origin history writes.
var IsolationFailureFields = [2]string{
	"_cbea69cc75848034ce0989bf",
	"_574ffb5982e23ad01867497c",
}

// Stylesheet probe fields.
const (
	StylesheetsText = "_cba4128a59ca994d6b27ce03"
	StylesheetsHash = "_834fbaa6a8bf091fdca82035"
)

// ErrorMessageLengthResult is the error message length probe's result.
const (
	ErrorMessageLengthResult = "_9965ce2e48f2fcde9b48a5ed"
)

// Image probe fields.
const (
	ImageWidth         = "_649c29b5a891b13039f9a0ba"
	ImageHeight        = "_1b8a6e7c70da2950e81f0f54"
	ImageEffectiveType = "_5930e40e97b074bf625978b2"
	ImageOnline        = "_bceebfedb12b49ea0e29ea48"
	ImageComplete      = "_aa9305b32ef2858c5c1250cd"
	ImageNaturalWidth  = "_fced4ca944afed284f7499e1"
	ImageTimestamp     = "_2062942b21d57db68286e7c0"
	ImageLoadError     = "_7f2f9bbc902256aec1b764cd"
	ImagePending       = "_df4785fdfca109a9f0592a9f"
	ImageWorkerTimeout = "_b2467a5a08275e8d86927c48"
	ImageAwaiting      = "_0a73a3a4a92c73005733d26a"
)

// Media (WebRTC) probe fields.
const (
	MediaState           = "_56e7c363edf4482d2a652039"
	MediaCodecs          = "_da6b6baf45bcd89bee78c361"
	MediaCandidates      = "_3876a4914983c02ab62380d7"
	MediaSDP             = "_bf827711f1af5e3877b04536"
	MediaSupport         = "_9f106978463140319e091736"
	MediaICEState        = "_0551c794bd86a1c60abe95a0"
	MediaUnavailable     = "_c658c1c6899af57ec6c39c2e"
	MediaCandidate       = "_e79bddbb1ba20cdb230fff3d"
	MediaCandidateTime   = "_c1ebce96d91a7cff088c8f77"
	MediaDataChannel     = "_b784bcb4bd9d5da3adc79aa0"
	MediaReused          = "_b6b9dbcd14fe11f6c765ca3c"
	MediaPriorCount      = "_f6579beb0695ae421f105a89"
	MediaFirstCandidate  = "_2cbbff49f6edc186c6692e8e"
	MediaElapsed         = "_03c985885a4a85a179027a60"
	MediaChannelError    = "_200177ecf732d1c3cd29cb5c"
	MediaSeedOfferError  = "_3cf67a623238585caf0b8128"
	MediaSeedGatherError = "_c0c335f78959467ef4c758c6"
)

// NetworkInformationOutputs are the network information probe's output fields.
var NetworkInformationOutputs = [6]string{
	"_fbc335568884e8039f111ddc",
	"_7fb7983b147a359ae1605761",
	"_8916475b09ac849d4b33b4eb",
	"_5ad8840411cfcba6a07a8f90",
	"_f53bae0a78ed600a46b3a07a",
	"_43f08fae15abd0265e7f71e9",
}

// Private token probe fields.
const (
	PrivateTokenElapsed       = "_8db99c6a16533752bb1bbed2"
	PrivateTokenError         = "_28023293e58744bd41fbf35c"
	PrivateTokenToken         = "_07fa7e9ab60f9de64248e36c"
	PrivateTokenTimestamp     = "_95f5893bd1c7feb85a3c2768"
	PrivateTokenTimeoutError  = "_b4788c77fdc4276b724c5cfe"
	PrivateTokenWorkerReplied = "_9050e5ce306b2a8a9468aa2f"
	PrivateTokenWorkerError   = "_3749b38b2e2d5390d14e6e8b"
)

// Worker fetch probe fields.
const (
	WorkerFetchStatus        = "_c6ca4de2162f12143f06c7e0"
	WorkerFetchToken         = "_c8171b29101f2dfc039b3e28"
	WorkerNavigatorIndicator = "_6221c83a1c236170f75c7a93"
	WorkerNavigatorResult    = "_b882c66155596222560e6f1b"
)
