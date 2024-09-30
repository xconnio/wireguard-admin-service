package wireguard_admin_service

import (
	"os/user"
)

func IsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	return currentUser.Uid == "0"
}
