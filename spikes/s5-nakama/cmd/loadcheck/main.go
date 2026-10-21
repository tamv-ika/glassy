// Command loadcheck loads a Go runtime plugin the way Nakama v3.41.0 does (plugin.Open, Lookup
// "InitModule", the same function type assertion) and checks that InitModule registers a
// FleetManager. It needs no database, unlike a real Nakama.
//
// Build it with the plugin's toolchain and flags: go run -trimpath ./cmd/loadcheck glassy-fm.so
//
// THROWAWAY: SP0 spike code.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"plugin"

	"github.com/heroiclabs/nakama-common/runtime"
)

// recordingInitializer implements only RegisterFleetManager; the embedded nil interface makes
// any other call panic, which would flag an unexpected registration.
type recordingInitializer struct {
	runtime.Initializer
	fleetManager runtime.FleetManagerInitializer
}

func (r *recordingInitializer) RegisterFleetManager(fm runtime.FleetManagerInitializer) error {
	r.fleetManager = fm
	return nil
}

type stderrLogger struct{ runtime.Logger }

func (stderrLogger) Info(format string, v ...any) { fmt.Fprintf(os.Stderr, format+"\n", v...) }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "loadcheck:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: loadcheck PLUGIN.so")
	}
	p, err := plugin.Open(args[0])
	if err != nil {
		return err
	}
	sym, err := p.Lookup("InitModule")
	if err != nil {
		return err
	}
	initModule, ok := sym.(func(context.Context, runtime.Logger, *sql.DB, runtime.NakamaModule, runtime.Initializer) error)
	if !ok {
		return fmt.Errorf("InitModule has type %T, not the one Nakama expects", sym)
	}
	initializer := &recordingInitializer{}
	if err := initModule(context.Background(), stderrLogger{}, nil, nil, initializer); err != nil {
		return fmt.Errorf("InitModule: %w", err)
	}
	if initializer.fleetManager == nil {
		return fmt.Errorf("InitModule registered no FleetManager")
	}
	fmt.Printf("OK: InitModule registered %T\n", initializer.fleetManager)
	return nil
}
