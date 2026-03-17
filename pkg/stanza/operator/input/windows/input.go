// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/input/windows"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	conventions "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/helper"
)

// Input is an operator that creates entries using the windows event log api.
type Input struct {
	helper.InputOperator
	singleInputWorker
	buffer                   *Buffer
	channel                  string
	ignoreChannelErrors      bool
	query                    *string
	maxReads                 int
	currentMaxReads          int
	startAt                  string
	raw                      bool
	includeLogRecordOriginal bool
	excludeProviders         map[string]struct{}
	pollInterval             time.Duration
	persister                operator.Persister
	publisherCache           publisherCache
	cancel                   context.CancelFunc
	subscription             Subscription
	maxEventsPerPollCycle    int
	remote                   RemoteConfig

	discoverDomainControllers bool

	// Worker registry
	workersMu sync.RWMutex
	workers   map[string]*singleInputWorker // key: normalised server name
}

// newInput creates a new Input operator.
func newInput(settings component.TelemetrySettings) *Input {
	basicConfig := helper.NewBasicConfig("windowseventlog", "input")
	basicOperator, _ := basicConfig.Build(settings)

	input := &Input{
		InputOperator: helper.InputOperator{
			WriterOperator: helper.WriterOperator{
				BasicOperator: basicOperator,
			},
		},
	}
	input.startRemoteSession = defaultStartRemoteSession
	return input
}

func newWorker(remote RemoteConfig, channel string, query *string, i *Input) *singleInputWorker {
	w := &singleInputWorker{
		remote:                remote,
		channel:               channel,
		query:                 query,
		startAt:               i.startAt,
		buffer:                NewBuffer(),
		bookmark:              NewBookmark(),
		publisherCache:        newPublisherCache(),
		maxReads:              i.maxReads,
		currentMaxReads:       i.currentMaxReads,
		maxEventsPerPollCycle: i.maxEventsPerPollCycle,
		pollInterval:          i.pollInterval,
		persister:             i.persister,
		logger:                i.Logger().With(zap.String("worker-server", remote.Server)),
		ignoreChannelErrors:   i.ignoreChannelErrors,
		startRemoteSession:    i.startRemoteSession,
		subscription:          i.subscription,
		processEvent:          i.processEvent,
	}
	return w
}

// isRemote checks if the input is configured for remote access.
func (i *Input) isRemote() bool {
	return i.remote.Server != ""
}

// isNonTransientError checks if the error is likely non-transient.
func isNonTransientError(err error) bool {
	return errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// Start will start reading events from a subscription.
func (i *Input) Start(persister operator.Persister) error {
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel

	i.persister = persister

	var workersList []*singleInputWorker
	if i.isRemote() {
		if i.discoverDomainControllers {
			domainControllers, err := getJoinedDomainControllersRemoteConfig(i.Logger(), i.remote.Username, i.remote.Password)
			if err != nil {
				i.Logger().Error("Failed to discover domain controllers for remote server, continuing with configured server only", zap.String("server", i.remote.Server), zap.Error(err))
			} else {
				for _, dc := range domainControllers {
					i.Logger().Info("Discovered domain controller for remote server", zap.String("server", i.remote.Server), zap.String("domain_controller", dc.Server))
					workersList = append(workersList, newWorker(dc, "Security", nil, i))
				}
			}
		}
	} else {
		// localhost events
		i.Logger().Info("domain controller discovery is not applicable for local server, ignoring discover_domain_controllers setting and reading from local event logs only")
		i.remote = RemoteConfig{
			Server:   "",
			Domain:   "",
			Username: "",
			Password: "",
		}
	}
	workersList = append(workersList, newWorker(i.remote, i.channel, i.query, i))
	i.publisherCache = newPublisherCache()
	i.workers = make(map[string]*singleInputWorker)

	for _, w := range workersList {
		if err := w.start(ctx); err != nil {
			if !i.ignoreChannelErrors {
				stopErr := i.stopAllWorkers()
				if stopErr != nil {
					return fmt.Errorf("failed to stop all workers: %w", stopErr)
				}
				return fmt.Errorf("failed to start worker %q: %w", w.remote.Server, err)
			}
			i.Logger().Warn("Failed to start worker, skipping",
				zap.String("server", w.remote.Server), zap.Error(err))
			continue
		}
		i.workers[workerKey(w)] = w
	}
	return nil
}

func (i *Input) Stop() error {
	// Warning: all calls made below must be safe to be done even if Start() was not called or failed.

	if i.cancel != nil {
		i.cancel()
	}
	return i.stopAllWorkers()
}

func (i *Input) stopAllWorkers() error {
	i.workersMu.Lock()
	defer i.workersMu.Unlock()
	var errs error
	for key, w := range i.workers {
		errs = multierr.Append(errs, w.stop())
		delete(i.workers, key)
	}
	return errs
}

func (i *Input) getPublisherName(event Event) (name string, excluded bool) {
	providerName, err := event.GetPublisherName(i.buffer)
	if err != nil {
		i.Logger().Error("Failed to get provider name", zap.Error(err))
		return "", true
	}
	if _, exclude := i.excludeProviders[providerName]; exclude {
		return "", true
	}

	return providerName, false
}

func (i *Input) renderSimpleAndSend(ctx context.Context, event Event, config RemoteConfig) error {
	simpleEvent, err := event.RenderSimple(i.buffer)
	if err != nil {
		return fmt.Errorf("render simple event: %w", err)
	}
	return i.sendEvent(ctx, simpleEvent, config)
}

func (i *Input) renderDeepAndSend(ctx context.Context, event Event, publisher Publisher, config RemoteConfig) error {
	deepEvent, err := event.RenderDeep(i.buffer, publisher)
	if err == nil {
		return i.sendEvent(ctx, deepEvent, config)
	}
	return multierr.Append(
		fmt.Errorf("render deep event: %w", err),
		i.renderSimpleAndSend(ctx, event, config),
	)
}

// processEvent will process and send an event retrieved from windows event log.
func (i *Input) processEventWithoutRenderingInfoCustomRemote(ctx context.Context, event Event, config RemoteConfig) error {
	if len(i.excludeProviders) == 0 {
		return i.renderSimpleAndSend(ctx, event, config)
	}
	if _, exclude := i.getPublisherName(event); exclude {
		return nil
	}
	return i.renderSimpleAndSend(ctx, event, config)
}

func (i *Input) processEventWithRenderingInfoCustomRemote(ctx context.Context, event Event, config RemoteConfig) error {
	providerName, exclude := i.getPublisherName(event)
	if exclude {
		return nil
	}

	publisher, err := i.publisherCache.get(providerName)
	if err != nil {
		return multierr.Append(
			fmt.Errorf("open event source for provider %q: %w", providerName, err),
			i.renderSimpleAndSend(ctx, event, config),
		)
	}

	if publisher.Valid() {
		return i.renderDeepAndSend(ctx, event, publisher, config)
	}
	return i.renderSimpleAndSend(ctx, event, config)
}

// sendEvent will send EventXML as an entry to the operator's output.
func (i *Input) sendEvent(ctx context.Context, eventXML *EventXML, remote RemoteConfig) error {
	var body any = eventXML.Original
	if !i.raw {
		body = formattedBody(eventXML)
	}

	e, err := i.NewEntry(body)
	if err != nil {
		return fmt.Errorf("create entry: %w", err)
	}

	e.Timestamp = parseTimestamp(eventXML.TimeCreated.SystemTime)
	e.Severity = parseSeverity(eventXML.RenderedLevel, eventXML.Level)

	if i.remote.Server != "" {
		e.AddAttribute("server.address", remote.Server)
	}

	if i.includeLogRecordOriginal {
		e.AddAttribute(string(conventions.LogRecordOriginalKey), eventXML.Original)
	}

	return i.Write(ctx, e)
}
