// Package main is the S5 spike: a Nakama Go runtime plugin that registers the glassy
// FleetManager backed by a fake broker. Build with -buildmode=plugin.
//
// THROWAWAY: SP0 spike code.
package main

import (
	"context"
	"database/sql"

	"github.com/heroiclabs/nakama-common/runtime"
)

// InitModule is the entry point Nakama looks up in every Go plugin.
func InitModule(ctx context.Context, logger runtime.Logger, db *sql.DB, nk runtime.NakamaModule, initializer runtime.Initializer) error {
	if err := initializer.RegisterFleetManager(New(NewFakeBroker(), "default")); err != nil {
		return err
	}
	logger.Info("glassy fleet manager registered (fake broker)")
	return nil
}
