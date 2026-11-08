package cli

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
)

// Exit codes of `dbgw query`.
const (
	ExitFailure = 1 // the statement failed, or the command could not run
	ExitDenied  = 2 // denied by dbgateway
	ExitPending = 3 // submitted for approval; not executed yet
)

// ExitCodeError ends the process with Code. The command has already
// printed everything the user needs, so nothing more is printed.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// ExitCode returns the process exit code.
func (e *ExitCodeError) ExitCode() int { return e.Code }

// apiError turns an RPC error into a message for people.
func apiError(err error) error {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return err
	}
	switch ce.Code() {
	case connect.CodeUnauthenticated:
		return fmt.Errorf("%w (server: %s)", errNotLoggedIn, ce.Message())
	case connect.CodeUnimplemented:
		return fmt.Errorf("the server does not support this command (is it an older dbgateway?): %s", ce.Message())
	}
	if ce.Message() == "" {
		return fmt.Errorf("request failed: %s", ce.Code())
	}
	return errors.New(ce.Message())
}
