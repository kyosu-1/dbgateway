package notify

import (
	"context"
	"time"

	"github.com/kyosu-1/dbgateway/internal/events"
)

// configVersionKey is the notify_state key of the last seen version.
const configVersionKey = "config_version"

// ConfigChanged records cfgVersion as the configuration version of this
// start and reports whether it differs from the version recorded at the
// previous start. The very first start (nothing recorded) is not a change.
func ConfigChanged(ctx context.Context, st StateStore, cfgVersion string) (changed bool, previous string, err error) {
	previous, found, err := st.SwapNotifyState(ctx, configVersionKey, cfgVersion, time.Now())
	if err != nil {
		return false, "", err
	}
	return found && previous != cfgVersion, previous, nil
}

// ConfigChangedEvent is the config_changed event for a version change.
func ConfigChangedEvent(previous, version string) events.Event {
	return events.Event{
		Type: events.ConfigChanged, Time: time.Now(),
		Detail: map[string]string{"previous_version": previous, "version": version},
	}
}
