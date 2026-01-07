package qdef

// ListMachinesReq parameters for the list-machines RPC.
type ListMachinesReq struct {
	ShowUnprovisioned bool `cbor:"show_unprovisioned"`
}

// ListMachinesResp response from list-machines RPC.
type ListMachinesResp struct {
	Hosts []HostState `cbor:"hosts"`
}

// ProvisionReq parameters for provision-machine RPC.
type ProvisionReq struct {
	Fingerprint []string `cbor:"fingerprint"`
}
