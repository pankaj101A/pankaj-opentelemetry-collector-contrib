package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

type remoteWorker struct {
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
	wg     sync.WaitGroup
	logger *zap.Logger

	// Callback into parent (stateless, safe to share)
	processEvent func(context.Context, Event, RemoteConfig) error
}

func (w *remoteWorker) start(ctx context.Context) error {
	// 1. Open RPC session (no-op for local)
	if w.isRemote() {
		if err := w.startSession(); err != nil {
			return fmt.Errorf("start session %q: %w", w.remote.Server, err)
		}
	}
	w.subscription = w.initSubscription()
	// 2. Load or initialise bookmark
	_, err := w.loadBookmark(ctx)
	if err != nil {
		return err
	}

	// 3. Open subscription
	//    When offsetXML != "", bookmark drives position; startAt is ignored by the API.
	//    When offsetXML == "", startAt ("beginning" | "end") drives position.
	// removed subscriptionError
	if err := w.subscription.Open(w.startAt, uintptr(w.sessionHandle), w.channel, w.query, w.bookmark); err != nil {
		var errorString string
		if isNonTransientError(err) {
			if w.isRemote() {
				errorString = fmt.Sprintf("failed to open subscription for remote server: %s", w.remote.Server)
			} else {
				errorString = "failed to open local subscription"
			}
			w.logger.Warn(errorString, zap.Error(err))
			return err
		} else {
			if w.isRemote() {
				w.logger.Warn("Transient error opening subscription for remote server, continuing", zap.String("server", w.remote.Server), zap.Error(err))
			} else {
				w.logger.Warn("Transient error opening local subscription, continuing", zap.Error(err))
			}
		}
		w.logger.Warn("Transient error opening subscription", zap.Error(err))
	}
	// 4. Start independent poll goroutine
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.wg.Add(1)
	go w.pollAndRead(workerCtx)
	return nil
}

func (w *remoteWorker) stop() error {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	var errs error
	if err := w.subscription.Close(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close subscription: %w", err))
	}

	if err := w.bookmark.Close(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close bookmark: %w", err))
	}

	if err := w.publisherCache.evictAll(); err != nil {
		errs = multierr.Append(errs, fmt.Errorf("failed to close publishers: %w", err))
	}

	return multierr.Append(errs, w.stopSession())
}

func (w *remoteWorker) startSession() error {
	if w.remote.Server == "" {
		return nil
	} // local
	login := EvtRPCLogin{
		Server:   windows.StringToUTF16Ptr(w.remote.Server),
		User:     windows.StringToUTF16Ptr(w.remote.Username),
		Password: windows.StringToUTF16Ptr(w.remote.Password),
	}
	if w.remote.Domain != "" {
		login.Domain = windows.StringToUTF16Ptr(w.remote.Domain)
	}
	handle, err := evtOpenSession(EvtRPCLoginClass, &login, 0, 0)
	if err != nil {
		return fmt.Errorf("evtOpenSession %s: %w", w.remote.Server, err)
	}
	w.sessionHandle = handle
	return nil
}

func (w *remoteWorker) stopSession() error {
	if w.sessionHandle == 0 {
		return nil
	}
	if err := evtClose(uintptr(w.sessionHandle)); err != nil {
		return fmt.Errorf("failed to close remote session handle for server %s: %w", w.remote.Server, err)
	}
	w.sessionHandle = 0
	return nil
}

func (w *remoteWorker) resubscribe(ctx context.Context) error {
	w.logger.Info("Resubscribing", zap.String("server", w.remote.Server))

	if err := w.subscription.Close(); err != nil {
		return err
	}
	if err := w.stopSession(); err != nil {
		return err
	}

	w.subscription = w.initSubscription()
	if err := w.startSession(); err != nil {
		return err
	}

	return w.subscription.Open(
		w.startAt,
		uintptr(w.sessionHandle),
		w.channel,
		w.query,
		w.bookmark, // ← resume from cursor, not from startAt
	)
}

func (w *remoteWorker) pollAndRead(ctx context.Context) {
	defer w.wg.Done()
	for {
		w.eventsReadInPollCycle = 0
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.pollInterval):
			w.read(ctx)
		}
	}
}

func (i *remoteWorker) read(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !i.readBatch(ctx) {
				return
			}
		}
	}
}

func (w *remoteWorker) readBatch(ctx context.Context) bool {
	maxBatchSize := w.getCurrentBatchSize()
	if maxBatchSize <= 0 {
		return false
	}

	events, actualMaxReads, err := w.subscription.Read(maxBatchSize)

	//	// Update the current max reads if it changed
	if err == nil && actualMaxReads < maxBatchSize {
		w.currentMaxReads = actualMaxReads
		w.logger.Debug("Encountered RPC_S_INVALID_BOUND, reduced batch size", zap.Int("current_batch_size", w.currentMaxReads), zap.Int("original_batch_size", w.maxReads))
	}

	//	resubscribe on any error, including transient ones,
	//	to recover from transient RPC issues without operator intervention. The bookmark ensures we won't lose events.
	if err != nil {
		w.logger.Error("Failed to read events from subscription", zap.Error(err))
		if w.isRemote() && (errors.Is(err, windows.ERROR_INVALID_HANDLE) || errors.Is(err, errSubscriptionHandleNotOpen)) {
			w.logger.Info("Resubscribing, closing remote subscription")
			closeErr := w.subscription.Close()
			if closeErr != nil {
				w.logger.Error("Failed to close remote subscription", zap.Error(closeErr))
				return false
			}
			if err := w.stopSession(); err != nil {
				w.logger.Error("Failed to close remote session", zap.Error(err))
			}
			w.logger.Info("Resubscribing, creating remote subscription")
			w.subscription = w.initSubscription()
			if err := w.startSession(); err != nil {
				w.logger.Error("Failed to re-establish remote session", zap.String("server", w.remote.Server), zap.Error(err))
				return false
			}
			if err := w.subscription.Open(w.startAt, uintptr(w.sessionHandle), w.channel, w.query, w.bookmark); err != nil {
				w.logger.Error("Failed to re-open subscription for remote server", zap.String("server", w.remote.Server), zap.Error(err))
				return false
			}
		}
		return false
	}

	for n, event := range events {
		if err := w.processEvent(ctx, event, w.remote); err != nil {
			w.logger.Error("process event", zap.Error(err))
		}
		if len(events) == n+1 {
			w.updateBookmarkOffset(ctx, event)
			if err := w.subscription.bookmark.Update(event); err != nil {
				w.logger.Error("Failed to update bookmark from event", zap.Error(err))
			}
		}
		event.Close()
	}

	w.eventsReadInPollCycle += len(events)
	return len(events) != 0
}

func (w *remoteWorker) updateBookmarkOffset(ctx context.Context, event Event) {
	if err := w.bookmark.Update(event); err != nil { /* log, return */
	}

	bookmarkXML, err := w.bookmark.Render(w.buffer)
	if err != nil { /* log, return */
	}

	if err := w.persister.Set(ctx, w.getPersistKey(), []byte(bookmarkXML)); err != nil {
		// Non-fatal: at-least-once delivery. Last batch may re-read on restart.
		w.logger.Error("Failed to persist bookmark", zap.Error(err))
	}
}

func (w *remoteWorker) loadBookmark(ctx context.Context) (string, error) {
	key := w.getPersistKey()
	bytes, err := w.persister.Get(ctx, key)
	if err != nil {
		_ = w.persister.Delete(ctx, key)
		return "", nil // start fresh
	}
	offsetXML := string(bytes)
	if offsetXML != "" {
		if err := w.bookmark.Open(offsetXML); err != nil {
			w.logger.Error("Failed to open persisted bookmark",
				zap.String("key", key),
				zap.String("offset_xml", offsetXML),
				zap.Error(err))
			return "", err
		}
	}
	return offsetXML, nil
}

func (w *remoteWorker) getPersistKey() string {
	var base string
	if w.query != nil {
		base = *w.query
	} else {
		base = w.channel
	}
	if w.remote.Server == "" {
		return base // local — backward compatible
	}
	return fmt.Sprintf("remote::%s::%s",
		strings.ToLower(strings.TrimSpace(w.remote.Server)),
		base,
	)
}

// isRemote checks if the input is configured for remote access.
func (i *remoteWorker) isRemote() bool {
	return i.remote.Server != ""
}

func (i *remoteWorker) getCurrentBatchSize() int {
	if i.maxEventsPerPollCycle == 0 {
		return i.currentMaxReads
	}
	return min(i.currentMaxReads, i.maxEventsPerPollCycle-i.eventsReadInPollCycle)
}

func (rm *remoteWorker) initSubscription() Subscription {
	if rm.isRemote() {
		return NewRemoteSubscription(rm.remote.Server)
	}
	return NewLocalSubscription()
}
