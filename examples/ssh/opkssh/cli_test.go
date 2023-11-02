package main

import (
	"strings"
	"testing"

	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/pktoken"
)

var (
	userArg    = "e0"
	typeArg    = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	certB64Arg = "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgfH0K7viCRHNeSwrMhiH36R7n9HFmg/6BMKwkWKMlZ48AAAAIbmlzdHAyNTYAAABBBGKNstWRSzoerpxFxrNXGCvIDkmBkMvlLE+CDlbbpf5MtNpR1kyG4HqMcVfo1pAYq/b9PH65rJjalYTn8DbPfLgAAAAAAAAAAAAAAAEAAAAeYW5vbi5hdXRob3IuYWFyZHZhcmtAZ21haWwuY29tAAAAAAAAAAAAAAAA//////////8AAAAAAAAKAAAAAA5vcGVucHVia2V5LXBrdAAACWgAAAlkZXlKd1lYbHNiMkZrSWpvaVpYbEtjR016VFdsUGFVcHZaRWhTZDJONmIzWk1Na1pxV1RJNU1XSnVVbnBNYldSMllqSmtjMXBUTldwaU1qQnBURU5LYUdWdVFXbFBhVWw0VDBSUk5VNXFaM2hOZW1jMVRYcG5kRnA2Um0xYVIxSnpUbGhTYm1KSE9ETmlWelZ6V1cxU2FHRjZhRzlaYms1NFlVZG9iVTU2YkcxTmVrbDFXVmhDZDJONU5XNWlNamx1WWtkV01XTXlWbmxaTWpsMVpFZFdkV1JETldwaU1qQnBURU5LYUdSWFVXbFBhVWw0VDBSUk5VNXFaM2hOZW1jMVRYcG5kRnA2Um0xYVIxSnpUbGhTYm1KSE9ETmlWelZ6V1cxU2FHRjZhRzlaYms1NFlVZG9iVTU2YkcxTmVrbDFXVmhDZDJONU5XNWlNamx1WWtkV01XTXlWbmxaTWpsMVpFZFdkV1JETldwaU1qQnBURU5LZW1SWFNXbFBhVWw0VFVSUk5FNVVTWGROUkVrd1RrUlJNMDVVVVhoTmVsbDVUbnBGYVV4RFNteGlWMFp3WWtOSk5rbHRSblZpTWpSMVdWaFdNR0ZIT1hsTWJVWm9ZMjFTTWxsWVNuSlJSMlIwV1Zkc2MweHRUblppVTBselNXMVdkRmxYYkhOWU0xcHNZMjFzYldGWFZtdEphbkF3WTI1V2JFeERTbWhrUmpsdldWaE9iMGxxYjJsU1JqbFdWa1YwVEdSVlVsWmpia1pPV2pOV1VsTXdWbWhVVldoaFVWTkpjMGx0TlhaaWJVNXNTV3B2YVdSRmFFSlRNblJSWlVWd2RsZHRPSGRoTURGMVZtdEdVbU13YzNwVE1uTXpZVzFHVkdOVE1VdGlWVkpMVjFaR1JGbFlSbFZVYTJoc1dubEpjMGx0TldoaVYxVnBUMmxLUW1KdE9YVmxWekYyWkZoTloxRllWakJoUnpsNVNXbDNhV05IYkdwa1NGWjVXbE5KTmtsdGFEQmtTRUo2VDJrNGRtSkhaM3BNYldSMllqSmtjMXBZVm5wYVdFcHFZakkxTUZwWE5UQk1iVTUyWWxNNWFFd3dSa1JhZW1oMldUQndhbFpHVmpOU2ExSkRXREZrUkV4VVpFNVJNbk15VGxSU2JGSklVbUZXYlRWNFpHdGtObVZxYkZOVVV6RldVakZzY0U1SVZqVk9NakZ1VUZoTk5VNXBNV3BKYVhkcFdqSnNNbHBYTldaaWJVWjBXbE5KTmtsclJuVmlNalUxWWxjNU1XTjVTWE5KYlZwb1lsZHNjMlZXT1hWWlZ6RnNTV3B2YVZGWVZqQmhSemw1U1dsM2FXSkhPV3BaVjNoc1NXcHZhVnBYTkdsTVEwcHdXVmhSYVU5cVJUSlBWR2Q1VFVSQmVrMUVTWE5KYlZZMFkwTkpOazFVV1RWUFJFbDNUWHByZDAxdU1DSXNJbk5wWjI1aGRIVnlaWE1pT2x0N0luQnliM1JsWTNSbFpDSTZJbVY1U21oaVIyTnBUMmxLUmxWNlNURk9hVWx6U1c1S05rbHFiMmxhYWswd1RVUlJlbHBxVFRCWlZHTjZXa2RhYkU1cVRURk9la2w0V2tkSk1VNTZRbWhOVjFFd1drUnNhMDFFUVRCWmVsRTFUWHBuTlZsWFdYZE9WRTV0V1dwWk5FMVVUWGxaZWtKcVRrUlJOVTV0Vm1wTlUwbHpTVzVXZDJGNVNUWmxlVXBvWWtkamFVOXBTa1pWZWtreFRtbEpjMGx0VG5sa2FVazJTV3hCZEUxcVZUSkphWGRwWVROU05VbHFiMmxTVlUxcFRFTktORWxxYjJsWFZ6aDVaVlJHWVZKcmVGQmhSRm94WW10V1dWSXpUWGhaTVd4TVQwZGtVRlV4YkVoVldHdDBWbGhPVlU1RmJGQldibEl4WWtZNWNtUjVTWE5KYm10cFQybEtNRlJ1UWxOTlYzUTFVbnBTU1dOVk1XcFdiVnAyVFZoQ1FsZFlSbVpaYW14UlUwUlpNV05yY0hGWlYzaGFWa2MwTkZKSFNsRmFhM2h1U1c0eE9TSXNJbWhsWVdSbGNpSTZleUp6YVdkZmRIbHdaU0k2SW1OcFl5SjlMQ0p6YVdkdVlYUjFjbVVpT2lKbGNVRjVUemN3VlZsVldYQnNSVlZKT0ZJNFFUZGhjMUZ2UzJSaWRIWnFjVGwyUTNsTlRGOWtWRTFhYWtsTlZYWlJRVWRNZDIxelVHTlZXVEZRZEZZM1pqQlBSM2hHT0dOaWEyaHhRM3BIZDJWUlVEQnFkeUo5TEhzaWNISnZkR1ZqZEdWa0lqb2laWGxLYUdKSFkybFBhVXBUVlhwSk1VNXBTWE5KYlhSd1drTkpOa2x0UlhkT2JVWnRUVWRKTWs5SFJYbE5WRVUxV2tSWk5VMXRUbWhaZWxKb1dXMVpNRTFVVm0xYWFrMHpUMFJuZUUxNldtMU9hbFZwVEVOS01HVllRV2xQYVVwTFZqRlJhV1pSSWl3aWFHVmhaR1Z5SWpwN0luTnBaMTkwZVhCbElqb2liMmxrWXlKOUxDSnphV2R1WVhSMWNtVWlPaUp5WjJWSVRHNUZjM0IxVVhBeWJHNWlaV0ZFU0hRNGNtd3RRbGROU2xSR1pqTmFVMVZaWWtWMGJWWnBSbEZFZW1RemExUXRSR0puV0hKTGNGcEJhekJqZFZKSlFrUnhkemhyVUc5NWJGaFNVVlJTYlZsNlR6RnNNVmx4YmtKMU1VbHZaR00xV0hKMFEyMXhaRVZLYWpFeU1ITkpUazFKWVRadlRHMVdjWEJwUm05aVRWUkpNblZJWlRONmQySjNibWxJZDFsMVdWWlhMVkpxTVZGeE5EbHlSQzFOVG5nM1ptRjNaVTVPTkRNelQxUmllWG94WVRGNVlWTXlTa2xFWVZKak1UVjFTa050WjFGTFR6WTRUa0ZMY3pkaVNscElUVmhzY1V4bVNrbFJhemR5VEdWTmNVbE5VSFkzU1c5dGFVZG5VelpTYlc1M1RtVlVSbWwyVUU1RGIxOUxNMTlmT1Y5TVVuUk5NV1ZmYzJ0eWEyZE9jMlZ4ZVhKUGNqRkdSMlpTWTJ0WVZHVkVkeTAzUVZRd00wUTBVSFpFYUhaRlpXaFJTRmxRT1doa1ZHZFZOVGg2Y20weFRVeGpVWFpQTkd4TFNVMUVPRUVpZlYxOQAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAaAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRijbLVkUs6Hq6cRcazVxgryA5JgZDL5SxPgg5W26X+TLTaUdZMhuB6jHFX6NaQGKv2/Tx+uayY2pWE5/A2z3y4AAAAZAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAASQAAACEA0KZwVOtx1r49OBvmLgrJKtu6PKofE2iJdhk66ZjggI0AAAAgIYTgdot6ziydvboQPb3KiUG1GOITddLlDvsFByJWBos="
)

func AllowAllPolicyEnforcer(userDesired string, pkt *pktoken.PKToken) error {
	return nil
}

func TestAuthorizedKeysCommand(t *testing.T) {
	op, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	pubkeyList, err := AuthorizedKeysCommand(userArg, typeArg, certB64Arg, AllowAllPolicyEnforcer, op)
	if err != nil {
		t.Error(err)
	}
	expectedPubkeyList := "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGKNstWRSzoerpxFxrNXGCvIDkmBkMvlLE+CDlbbpf5MtNpR1kyG4HqMcVfo1pAYq/b9PH65rJjalYTn8DbPfLg="
	if expectedPubkeyList != strings.TrimSpace(pubkeyList) {
		t.Error(err)
	}
}
