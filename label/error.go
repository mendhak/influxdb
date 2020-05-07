package label

import (
	"github.com/influxdata/influxdb/v2"
)

var (
	// NotUniqueIDError occurs when attempting to create a Label with an ID that already belongs to another one
	NotUniqueIDError = &influxdb.Error{
		Code: influxdb.EConflict,
		Msg:  "ID already exists",
	}
)
