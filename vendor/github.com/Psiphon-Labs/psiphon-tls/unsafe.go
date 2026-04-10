// unsafe.go is based on qtls/unsafe.go
// https://github.com/quic-go/qtls-go1-20/blob/49f389c17d984e5b248f0a57cbae10dd4198a3bf/unsafe.go
/* Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package tls

import "crypto/tls"

// Go's stdlib ConnectionState layout changes across patch releases, and the
// Android build here only needs the exported view consumed by callers like
// net/http and quic-go tracing. Copy fields explicitly instead of depending on
// identical private layout and unsafe pointer casts.
func UnsafeFromConnectionState(ss *ConnectionState) *tls.ConnectionState {
	if ss == nil {
		return nil
	}
	return &tls.ConnectionState{
		Version:                     ss.Version,
		HandshakeComplete:           ss.HandshakeComplete,
		DidResume:                   ss.DidResume,
		CipherSuite:                 ss.CipherSuite,
		NegotiatedProtocol:          ss.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  ss.NegotiatedProtocolIsMutual,
		ServerName:                  ss.ServerName,
		PeerCertificates:            ss.PeerCertificates,
		VerifiedChains:              ss.VerifiedChains,
		SignedCertificateTimestamps: ss.SignedCertificateTimestamps,
		OCSPResponse:                ss.OCSPResponse,
		TLSUnique:                   ss.TLSUnique,
		ECHAccepted:                 ss.ECHAccepted,
	}
}

func UnsafeToConnectionState(ss *tls.ConnectionState) *ConnectionState {
	if ss == nil {
		return nil
	}
	return &ConnectionState{
		Version:                     ss.Version,
		HandshakeComplete:           ss.HandshakeComplete,
		DidResume:                   ss.DidResume,
		CipherSuite:                 ss.CipherSuite,
		NegotiatedProtocol:          ss.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  ss.NegotiatedProtocolIsMutual,
		ServerName:                  ss.ServerName,
		PeerCertificates:            ss.PeerCertificates,
		VerifiedChains:              ss.VerifiedChains,
		SignedCertificateTimestamps: ss.SignedCertificateTimestamps,
		OCSPResponse:                ss.OCSPResponse,
		TLSUnique:                   ss.TLSUnique,
		ECHAccepted:                 ss.ECHAccepted,
	}
}
