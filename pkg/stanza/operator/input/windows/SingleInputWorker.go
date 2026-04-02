// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/input/windows"

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/internal/metadata"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
)

// singleInputWorker
// Implementation is to encapsulate all logic required to collect Windows Event Logs from a single source
// — whether that source is the local machine or a remotely discovered Domain Controller (DC).
// It provides an isolated, self‑contained worker that can be started, managed, and stopped by the higher‑level Input orchestrator.
// It sends events to the parent Input operator via a callback, allowing the parent to remain stateless and focused on orchestration,
// while the singleInputWorker handles all the complexities of interacting with the Windows Event Log API,
// managing bookmarks, handling remote sessions, and implementing robust error handling and recovery logic.
// ***
type singleInputWorker struct {
	// Identity
	remote  RemoteConfig // empty Server = local
	channel string
	query   *string
	startAt string // used only when no persisted bookmark exists

	// Windows API handles — exclusive to this worker
	sessionHandle windows.Handle
	subscription  Subscription
	bookmark      Bookmark
	buffer        *Buffer

	// Per-worker publisher cache (no contention, slight memory trade-off)
	publisherCache publisherCache

	// Batch sizing
	maxReads              int
	currentMaxReads       int
	maxEventsPerPollCycle int
	eventsReadInPollCycle int
	pollInterval          time.Duration

	// Shared persister ref — unique key per worker
	persister operator.Persister

	// Lifecycle
	cancel context.CancelFunc
	// cancelEvent is a manual-reset Windows event handle signaled by Stop() to unblock
	// WaitForMultipleObjects in awaitAndReadEvents. A plain context cancellation cannot
	// interrupt a blocking Windows syscall, so this handle bridges Go's cancellation model
	// to the Windows API layer.
	cancelEvent windows.Handle

	wg                  sync.WaitGroup
	logger              *zap.Logger
	ignoreChannelErrors bool
	startRemoteSession  func(worker *singleInputWorker) error
	waitTimeout         time.Duration

	// Callback into parent (stateless, safe to share)
	processEvent func(context.Context, Event, RemoteConfig) error
}

func (siw *singleInputWorker) start(ctx context.Context) error {
	// 1. Open RPC session (no-op for local)
	if siw.isRemote() {
		if err := siw.startRemoteSession(siw); err != nil {
			return fmt.Errorf("failed to start remote session for server %s: %w", siw.remote.Server, err)
		}
	}
	// 2. Load or initialize bookmark
	_, err := siw.loadBookmark(ctx)
	if err != nil {
		return err
	}

	// 3. Open subscription
	//    When offsetXML != "", bookmark drives position; startAt is ignored by the API.
	//    When offsetXML == "", startAt ("beginning" | "end") drives position.
	// removed subscriptionError
	subscription := siw.initSubscription()
	fmt.Printf("Opening subscription for server %s, channel %s, query %v, startAt %s handle %v \n", siw.remote.Server, siw.channel, siw.query, siw.startAt, siw.sessionHandle)
	if err := subscription.Open(siw.startAt, uintptr(siw.sessionHandle), siw.channel, siw.query, siw.bookmark); err != nil {
		var errorString string
		if isNonTransientError(err) {
			if siw.isRemote() {
				errorString = fmt.Sprintf("failed to open subscription for remote server: %s", siw.remote.Server)
			} else {
				errorString = "failed to open local subscription"
			}
			siw.logger.Warn(errorString, zap.Error(err))
			return fmt.Errorf("%s, error: %w", errorString, err)
		}
		if siw.isRemote() {
			siw.logger.Warn("Transient error opening subscription for remote server, continuing", zap.String("server", siw.remote.Server), zap.Error(err))
		} else {
			siw.logger.Warn("Transient error opening local subscription, continuing", zap.Error(err))
		}
	}
	// 4. Start independent poll goroutine
	siw.logger.Info(fmt.Sprintf("Started subscription for remote server: %s", siw.remote.Server))
	siw.subscription = subscription
	if metadata.StanzaWindowsEventDrivenScrapingFeatureGate.IsEnabled() {
		cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, initially non-signaled
		if err != nil {
			return fmt.Errorf("failed to create cancel event: %w", err)
		}
		siw.cancelEvent = cancelEvent
		siw.wg.Add(1)
		go siw.awaitAndReadEvents(ctx)
	} else {
		workerCtx, cancel := context.WithCancel(ctx)
		siw.cancel = cancel
		siw.wg.Add(1)
		go siw.pollAndRead(workerCtx)
	}

	return nil
}

func (siw *singleInputWorker) stop() error {
	if siw.cancel != nil {
		siw.cancel()
	}

	if siw.cancelEvent != 0 {
		// If this fails, wg.Wait() below will block forever since awaitAndReadEvents will never
		// return from WaitForMultipleObjects. Log loudly and continue.
		if err := windows.SetEvent(siw.cancelEvent); err != nil {
			siw.logger.Error("Failed to signal cancel event during stop; shutdown may hang", zap.Error(err))
		}
	}

	siw.wg.Wait()

	var errs error
	if siw.cancelEvent != 0 {
		if err := windows.CloseHandle(siw.cancelEvent); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("failed to close cancel event: %w", err))
		}
		siw.cancelEvent = 0
	}

	if err := siw.subscription.Close(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close subscription: %w", err))
	}

	if err := siw.bookmark.Close(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close bookmark: %w", err))
	}

	if err := siw.publisherCache.evictAll(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close publishers: %w", err))
	}

	return multierr.Append(errs, siw.stopSession())
}

func defaultStartRemoteSession(siw *singleInputWorker) error {
	// remote session is only needed if Server is specified; otherwise we stay local and sessionHandle remains 0
	if siw.remote.Server == "" {
		return nil
	}
	login := EvtRPCLogin{
		Server:   windows.StringToUTF16Ptr(siw.remote.Server),
		User:     windows.StringToUTF16Ptr(siw.remote.Username),
		Password: windows.StringToUTF16Ptr(siw.remote.Password),
	}
	if siw.remote.Domain != "" {
		login.Domain = windows.StringToUTF16Ptr(siw.remote.Domain)
	}
	handle, err := evtOpenSession(EvtRPCLoginClass, &login, 0, 0)
	if err != nil {
		return fmt.Errorf("evtOpenSession %s: %w", siw.remote.Server, err)
	}
	siw.sessionHandle = handle
	return nil
}

func (siw *singleInputWorker) stopSession() error {
	if siw.sessionHandle == 0 {
		return nil
	}
	if err := evtClose(uintptr(siw.sessionHandle)); err != nil {
		return fmt.Errorf("failed to close remote session handle for server %s: %w", siw.remote.Server, err)
	}
	siw.sessionHandle = 0
	return nil
}

// awaitAndReadEvents is the event-driven alternative to pollAndRead. Instead of sleeping
// for a fixed interval it blocks on a Windows wait object that is signaled by the subscription
// when new events arrive. This reduces latency and avoids unnecessary wakeups.
func (siw *singleInputWorker) awaitAndReadEvents(ctx context.Context) {
	defer siw.wg.Done()

	timeoutMs := uint32(siw.waitTimeout.Milliseconds())
	for {
		ready, err := siw.subscription.Wait(siw.cancelEvent, timeoutMs)
		if err != nil {
			siw.logger.Error("Failed to wait for subscription signal", zap.Error(err))
			return
		}
		if !ready {
			// cancel event was signaled
			return
		}

		siw.eventsReadInPollCycle = 0
		siw.read(ctx)
	}
}

func (siw *singleInputWorker) pollAndRead(ctx context.Context) {
	defer siw.wg.Done()
	for {
		siw.eventsReadInPollCycle = 0
		select {
		case <-ctx.Done():
			return
		case <-time.After(siw.pollInterval):
			siw.read(ctx)
		}
	}
}

func (siw *singleInputWorker) read(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !siw.readBatch(ctx) {
				return
			}
		}
	}
}

func (siw *singleInputWorker) readBatch(ctx context.Context) bool {
	maxBatchSize := siw.getCurrentBatchSize()
	if maxBatchSize <= 0 {
		return false
	}

	events, actualMaxReads, err := siw.subscription.Read(maxBatchSize)

	//	Update the current max reads if it changed
	if err == nil && actualMaxReads < maxBatchSize {
		siw.currentMaxReads = actualMaxReads
		siw.logger.Debug("Encountered RPC_S_INVALID_BOUND, reduced batch size", zap.Int("current_batch_size", siw.currentMaxReads), zap.Int("original_batch_size", siw.maxReads))
	}

	//	resubscribe on any error, including transient ones,
	//	to recover from transient RPC issues without operator intervention. The bookmark ensures we won't lose events.
	if err != nil {
		siw.logger.Error("Failed to read events from subscription", zap.Error(err))
		if siw.isRemote() && (errors.Is(err, windows.ERROR_INVALID_HANDLE) || errors.Is(err, errSubscriptionHandleNotOpen)) {
			siw.logger.Info("Resubscribing, closing remote subscription")
			closeErr := siw.subscription.Close()
			if closeErr != nil {
				siw.logger.Error("Failed to close remote subscription", zap.Error(closeErr))
				return false
			}
			if err := siw.stopSession(); err != nil {
				siw.logger.Error("Failed to close remote session", zap.Error(err))
			}
			siw.logger.Info("Resubscribing, creating remote subscription")
			siw.subscription = siw.initSubscription()
			if err := siw.startRemoteSession(siw); err != nil {
				siw.logger.Error("Failed to re-establish remote session", zap.String("server", siw.remote.Server), zap.Error(err))
				return false
			}
			if err := siw.subscription.Open(siw.startAt, uintptr(siw.sessionHandle), siw.channel, siw.query, siw.bookmark); err != nil {
				siw.logger.Error("Failed to re-open subscription for remote server", zap.String("server", siw.remote.Server), zap.Error(err))
				return false
			}
		}
		return false
	}

	for n, event := range events {
		if err := siw.processEvent(ctx, event, siw.remote); err != nil {
			siw.logger.Error("process event", zap.Error(err))
		}
		if len(events) == n+1 {
			siw.updateBookmarkOffset(ctx, event)
			if err := siw.subscription.bookmark.Update(event); err != nil {
				siw.logger.Error("Failed to update bookmark from event", zap.Error(err))
			}
		}
		event.Close()
	}

	siw.eventsReadInPollCycle += len(events)
	return len(events) != 0
}

func (siw *singleInputWorker) updateBookmarkOffset(ctx context.Context, event Event) {
	if err := siw.bookmark.Update(event); err != nil {
		siw.logger.Error("Failed to update bookmark from event", zap.Error(err), zap.String("server", siw.remote.Server))
		return
	}

	bookmarkXML, err := siw.bookmark.Render(siw.buffer)
	if err != nil {
		siw.logger.Error("Failed to render bookmark xml", zap.Error(err), zap.String("server", siw.remote.Server))
		return
	}

	if err := siw.persister.Set(ctx, siw.getPersistKey(), []byte(bookmarkXML)); err != nil {
		// Non-fatal: at-least-once delivery. Last batch may re-read on restart.
		siw.logger.Error("Failed to persist bookmark", zap.Error(err))
	}
}

func (siw *singleInputWorker) loadBookmark(ctx context.Context) (string, error) {
	key := siw.getPersistKey()
	bytes, err := siw.persister.Get(ctx, key)
	if err != nil {
		_ = siw.persister.Delete(ctx, key)
		return "", nil // start fresh
	}
	offsetXML := string(bytes)
	if offsetXML != "" {
		if err := siw.bookmark.Open(offsetXML); err != nil {
			siw.logger.Error("Failed to open persisted bookmark",
				zap.String("key", key),
				zap.String("offset_xml", offsetXML),
				zap.Error(err))
			return "", err
		}
	}
	return offsetXML, nil
}

func (siw *singleInputWorker) getPersistKey() string {
	var base string
	if siw.query != nil {
		base = *siw.query
	} else {
		base = siw.channel
	}
	if siw.remote.Server == "" {
		return base // local — backward compatible
	}
	return fmt.Sprintf("remote::%s::%s",
		strings.ToLower(strings.TrimSpace(siw.remote.Server)),
		base,
	)
}

// isRemote checks if the input is configured for remote access.
func (siw *singleInputWorker) isRemote() bool {
	return siw.remote.Server != ""
}

func (siw *singleInputWorker) getCurrentBatchSize() int {
	if siw.maxEventsPerPollCycle == 0 {
		return siw.currentMaxReads
	}
	return min(siw.currentMaxReads, siw.maxEventsPerPollCycle-siw.eventsReadInPollCycle)
}

func (siw *singleInputWorker) initSubscription() Subscription {
	if siw.isRemote() {
		return NewRemoteSubscription(siw.remote.Server, siw.logger)
	}
	return NewLocalSubscription(siw.logger)
}

func workerKey(worker *singleInputWorker) string {
	return fmt.Sprintf("%s_%s", strings.ToLower(strings.TrimSpace(worker.remote.Server)), worker.channel)
}
