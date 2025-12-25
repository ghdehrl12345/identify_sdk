package auth

import "github.com/ghdehrl12345/identify_sdk/common"

// PolicyBundle is a server-provided policy snapshot for client sync.
type PolicyBundle struct {
	Config        common.SharedConfig `json:"config"`
	ParamsVersion string              `json:"params_version"`
	VKID          string              `json:"vk_id"`
}
