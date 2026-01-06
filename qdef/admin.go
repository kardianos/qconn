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
	Hostname    string   `cbor:"hostname"`
	Address     string   `cbor:"address"`
	Provisioned bool     `cbor:"provisioned"`
	Roles       []string `cbor:"roles,omitempty"`
	Devices     []string `cbor:"devices,omitempty"`
}
