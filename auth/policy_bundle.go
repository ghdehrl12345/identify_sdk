package auth

import (
	"github.com/ghdehrl12345/identify_sdk/common"
	sdkerrors "github.com/ghdehrl12345/identify_sdk/errors"
)

// PolicyBundle is a server-provided policy snapshot for client sync.
type PolicyBundle struct {
	Config        common.SharedConfig `json:"config"`
	ParamsVersion string              `json:"params_version"`
	VKID          string              `json:"vk_id"`
}

// EnforcePolicy checks vk_id and params_version against the server bundle.
func EnforcePolicy(bundle PolicyBundle, vkID string, paramsVersion string) error {
	if vkID != "" && vkID != bundle.VKID {
		return sdkerrors.ErrKeyMismatch
	}
	if paramsVersion != "" && paramsVersion != bundle.ParamsVersion {
		return sdkerrors.ErrPolicyMismatch
	}
	return nil
}
