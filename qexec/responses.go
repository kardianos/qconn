package qexec

import "github.com/kardianos/qconn"

// RespServerReady indicates the server has started and is ready to accept connections.
type RespServerReady struct {
	Addr      string   // The actual listening address
	AuthToken qconn.TA // The auth token for admin self-authorization (only on new DB)
}

// RespAdminAuthed indicates the admin client has been authenticated.
type RespAdminAuthed struct {
	Fingerprint qconn.FP
	ConfigPath  string
}

// RespClientList contains a list of client records.
type RespClientList struct {
	Clients []*qconn.ClientRecord
}

// RespApproved indicates a client has been approved.
type RespApproved struct {
	Fingerprint qconn.FP
}

// RespRevoked indicates a client has been revoked.
type RespRevoked struct {
	Fingerprint qconn.FP
}

// RespTokenRotated indicates a provision token was sent to a client.
type RespTokenRotated struct {
	Fingerprint qconn.FP
}

// RespRenewalTriggered indicates certificate renewal was triggered on a client.
type RespRenewalTriggered struct {
	Fingerprint qconn.FP
}
