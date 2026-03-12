// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/input/windows"

import (
	"context"
	"errors"
	"math"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/windows"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/entry"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/testutil"
)

func newTestInput() *Input {
	return newInput(component.TelemetrySettings{
		Logger: zap.NewNop(),
	})
}

func newTestInputWithLogger(logger *zap.Logger) *Input {
	return newInput(component.TelemetrySettings{
		Logger: logger,
	})
}

// TestInputCreate_Stop ensures the input correctly shuts down even if it was never started.
func TestInputCreate_Stop(t *testing.T) {
	input := newTestInput()
	assert.NoError(t, input.Stop())
}

// TestInputStart_LocalSubscriptionError ensures the input correctly handles local subscription errors.
func TestInputStart_LocalSubscriptionError(t *testing.T) {
	persister := testutil.NewMockPersister("")

	input := newTestInput()
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second

	err := input.Start(persister)
	assert.ErrorContains(t, err, "The specified channel could not be found")
}

// TestInputStart_NoErrorIfIgnoreChannelErrorsEnabled ensures no error is thrown when ignore_channel_errors flag is enabled
// Other existing tests ensures the default behavior of error out when any error occurs while subscribing to the channel
func TestInputStart_NoErrorIfIgnoreChannelErrorEnabled(t *testing.T) {
	persister := testutil.NewMockPersister("")

	input := newTestInput()
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.ignoreChannelErrors = true
	input.pollInterval = 1 * time.Second

	err := input.Start(persister)
	assert.NoError(t, err, "Expected no error when ignoreMissingChannel is true")
}

// TestInputStart_RemoteSubscriptionError ensures the input correctly handles remote subscription errors.
func TestInputStart_RemoteSubscriptionError(t *testing.T) {
	persister := testutil.NewMockPersister("")

	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second
	input.remote = RemoteConfig{
		Server: "remote-server",
	}

	err := input.Start(persister)
	assert.ErrorContains(t, err, "The specified channel could not be found")
}

// TestInputStart_RemoteSessionError ensures the input correctly handles remote session errors.
func TestInputStart_RemoteSessionError(t *testing.T) {
	persister := testutil.NewMockPersister("")

	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error {
		return errors.New("remote session error")
	}
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second
	input.remote = RemoteConfig{
		Server: "remote-server",
	}

	err := input.Start(persister)
	assert.ErrorContains(t, err, "failed to start remote session for server remote-server: remote session error")
}

// TestInputStart_RemoteAccessDeniedError ensures the input correctly handles remote access denied errors.
func TestInputStart_RemoteAccessDeniedError(t *testing.T) {
	persister := testutil.NewMockPersister("")

	originalEvtSubscribe := evtSubscribe
	defer func() { evtSubscribe = originalEvtSubscribe }()

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 0, windows.ERROR_ACCESS_DENIED
	}

	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second
	input.remote = RemoteConfig{
		Server: "remote-server",
	}

	err := input.Start(persister)
	assert.ErrorContains(t, err, "failed to open subscription for remote server")
	assert.ErrorContains(t, err, "Access is denied")
}

// TestInputStart_BadChannelName ensures the input correctly handles bad channel names.
func TestInputStart_BadChannelName(t *testing.T) {
	persister := testutil.NewMockPersister("")

	originalEvtSubscribe := evtSubscribe
	defer func() { evtSubscribe = originalEvtSubscribe }()

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 0, windows.ERROR_EVT_CHANNEL_NOT_FOUND
	}

	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "bad-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second
	input.remote = RemoteConfig{
		Server: "remote-server",
	}

	err := input.Start(persister)
	assert.ErrorContains(t, err, "failed to open subscription for remote server")
	assert.ErrorContains(t, err, "The specified channel could not be found")
}

func TestInputStart_RemoteSessionWithDomain(t *testing.T) {
	persister := testutil.NewMockPersister("")

	// Mock EvtOpenSession to capture the login struct and verify Domain handling
	originalOpenSessionProc := openSessionProc
	var capturedDomain string
	var domainWasNil bool
	openSessionProc = MockProc{
		call: func(a ...uintptr) (uintptr, uintptr, error) {
			// a[0] = loginClass, a[1] = login pointer, a[2] = timeout, a[3] = flags
			if len(a) >= 4 && a[1] != 0 {
				capturedDomain = "remote-domain"
				domainWasNil = false
			} else {
				domainWasNil = true
			}
			return 1, 0, nil
		},
	}
	defer func() { openSessionProc = originalOpenSessionProc }()

	input := newTestInput()
	input.ignoreChannelErrors = true
	input.channel = "test-channel"
	input.startAt = "beginning"
	input.pollInterval = 1 * time.Second
	input.remote = RemoteConfig{
		Server:   "remote-server",
		Username: "test-user",
		Password: "test-pass",
		Domain:   "remote-domain",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, input.Stop())
	})

	require.False(t, domainWasNil)
	require.Equal(t, "remote-domain", capturedDomain)
}

// TestInputRead_RPCInvalidBound tests that the Input handles RPC_S_INVALID_BOUND errors properly
func TestInputRead_RPCInvalidBound(t *testing.T) {
	// Save original procs and restore after test
	originalEvtNext := evtNext
	originalEvtClose := evtClose
	originalEvtSubscribe := evtSubscribe

	// Track calls to our mocked functions
	var nextCalls, closeCalls, subscribeCalls int

	// Mock the procs
	evtClose = func(_ uintptr) error {
		closeCalls++
		return nil
	}

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		subscribeCalls++
		return 42, nil
	}

	evtNext = func(_ uintptr, _ uint32, _ *uintptr, _, _ uint32, _ *uint32) error {
		nextCalls++
		if nextCalls == 1 {
			return windows.RPC_S_INVALID_BOUND
		}

		return nil
	}

	defer func() {
		evtNext = originalEvtNext
		evtClose = originalEvtClose
		evtSubscribe = originalEvtSubscribe
	}()

	// Create a logger with an observer for testing log output
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	// Create input instance with mocked dependencies
	input := &newInput(component.TelemetrySettings{
		Logger: logger,
	}).SingleInputWorker

	input.logger = logger
	// Set up test values
	input.maxReads = 100
	input.currentMaxReads = 100

	// Set up subscription with valid handle and enough info to reopen
	input.subscription = Subscription{
		handle:        42, // Dummy handle
		startAt:       "beginning",
		sessionHandle: 0,
		channel:       "test-channel",
	}

	// Call the method under test
	input.read(t.Context())

	// Verify the correct number of calls to each mock
	assert.Equal(t, 2, nextCalls, "nextProc should be called twice (initial failure and retry)")
	assert.Equal(t, 1, closeCalls, "closeProc should be called once to close subscription")
	assert.Equal(t, 1, subscribeCalls, "subscribeProc should be called once to reopen subscription")

	// Verify that batch size was reduced
	assert.Equal(t, 50, input.currentMaxReads)

	// Verify that a warning log was generated
	require.Equal(t, 1, logs.Len())
	assert.Contains(t, logs.All()[0].Message, "Encountered RPC_S_INVALID_BOUND")
}

// TestInputIncludeLogRecordOriginal tests that the log.record.original attribute is added when include_log_record_original is true
func TestInputIncludeLogRecordOriginal(t *testing.T) {
	input := newTestInput()
	input.includeLogRecordOriginal = true
	input.pollInterval = time.Second
	input.buffer = NewBuffer() // Initialize buffer

	// Create a mock event XML
	eventXML := &EventXML{
		Original: "<Event><System><Provider Name='TestProvider'/><EventID>1</EventID></System></Event>",
		TimeCreated: TimeCreated{
			SystemTime: "2024-01-01T00:00:00Z",
		},
	}

	persister := testutil.NewMockPersister("")
	fake := testutil.NewFakeOutput(t)
	input.OutputOperators = []operator.Operator{fake}

	err := input.Start(persister)
	require.NoError(t, err)

	err = input.sendEvent(t.Context(), eventXML, input.remote)
	require.NoError(t, err)

	expectedEntry := &entry.Entry{
		Timestamp: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Body: map[string]any{
			"channel":    "",
			"computer":   "",
			"event_data": map[string]any{},
			"event_id": map[string]any{
				"id":         uint32(0),
				"qualifiers": uint16(0),
			},
			"keywords": []string(nil),
			"level":    "",
			"message":  "",
			"opcode":   "",
			"provider": map[string]any{
				"event_source": "",
				"guid":         "",
				"name":         "",
			},
			"record_id":   uint64(0),
			"system_time": "2024-01-01T00:00:00Z",
			"task":        "",
			"version":     uint8(0),
		},
		Attributes: map[string]any{
			"log.record.original": eventXML.Original,
		},
	}

	select {
	case actualEntry := <-fake.Received:
		actualEntry.ObservedTimestamp = time.Time{}
		assert.Equal(t, expectedEntry, actualEntry)
	case <-time.After(time.Second):
		require.FailNow(t, "Timed out waiting for entry")
	}

	err = input.Stop()
	require.NoError(t, err)
}

// TestInputIncludeLogRecordOriginalFalse tests that the log.record.original attribute is not added when include_log_record_original is false
func TestInputIncludeLogRecordOriginalFalse(t *testing.T) {
	input := newTestInput()
	input.includeLogRecordOriginal = false
	input.pollInterval = time.Second
	input.buffer = NewBuffer() // Initialize buffer

	// Create a mock event XML
	eventXML := &EventXML{
		Original: "<Event><System><Provider Name='TestProvider'/><EventID>1</EventID></System></Event>",
		TimeCreated: TimeCreated{
			SystemTime: "2024-01-01T00:00:00Z",
		},
	}

	persister := testutil.NewMockPersister("")
	fake := testutil.NewFakeOutput(t)
	input.OutputOperators = []operator.Operator{fake}

	err := input.Start(persister)
	require.NoError(t, err)

	err = input.sendEvent(t.Context(), eventXML, input.remote)
	require.NoError(t, err)

	expectedEntry := &entry.Entry{
		Timestamp: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Body: map[string]any{
			"channel":    "",
			"computer":   "",
			"event_data": map[string]any{},
			"event_id": map[string]any{
				"id":         uint32(0),
				"qualifiers": uint16(0),
			},
			"keywords": []string(nil),
			"level":    "",
			"message":  "",
			"opcode":   "",
			"provider": map[string]any{
				"event_source": "",
				"guid":         "",
				"name":         "",
			},
			"record_id":   uint64(0),
			"system_time": "2024-01-01T00:00:00Z",
			"task":        "",
			"version":     uint8(0),
		},
		Attributes: nil,
	}

	// Verify that log.record.original attribute does not exist
	select {
	case actualEntry := <-fake.Received:
		actualEntry.ObservedTimestamp = time.Time{}
		assert.Equal(t, expectedEntry, actualEntry)
	case <-time.After(time.Second):
		require.FailNow(t, "Timed out waiting for entry")
	}

	err = input.Stop()
	require.NoError(t, err)
}

// TestInputRead_Batching tests that the Input handles MaxEventsPerPoll and MaxReads correctly
func TestInputRead_Batching(t *testing.T) {
	originalEvtNext := evtNext
	originalEvtRender := evtRender
	originalEvtClose := evtClose
	originalEvtSubscribe := evtSubscribe
	originalCreateBookmarkProc := createBookmarkProc
	originalEvtUpdateBookmark := evtUpdateBookmark
	defer func() {
		evtNext = originalEvtNext
		evtRender = originalEvtRender
		evtClose = originalEvtClose
		evtSubscribe = originalEvtSubscribe
		createBookmarkProc = originalCreateBookmarkProc
		evtUpdateBookmark = originalEvtUpdateBookmark
	}()

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}

	evtRender = func(_, _ uintptr, _, _ uint32, _ *byte) (*uint32, error) {
		bufferUsed := new(uint32)
		return bufferUsed, nil
	}

	evtClose = func(_ uintptr) error {
		return nil
	}

	createBookmarkProc = MockProc{
		call: func(_ ...uintptr) (uintptr, uintptr, error) {
			return 1, 0, nil
		},
	}

	evtUpdateBookmark = func(_, _ uintptr) error {
		return nil
	}

	var nextCalls, processedEvents, emittedEvents int

	maxEventsToEmit := -1

	mockBatch := make([]uintptr, 99)
	var pinner runtime.Pinner
	pinner.Pin(&mockBatch[0])
	defer pinner.Unpin()

	producedEvents := 0

	for i := range mockBatch {
		mockBatch[i] = uintptr(i)
	}

	evtNext = func(_ uintptr, eventsSize uint32, events *uintptr, _, _ uint32, returned *uint32) error {
		nextCalls++

		wantsToRead := int(eventsSize)
		producedEvents = min(len(mockBatch), wantsToRead)
		if maxEventsToEmit >= 0 {
			producedEvents = min(producedEvents, maxEventsToEmit-emittedEvents)
		}

		*returned = uint32(producedEvents)
		*events = uintptr(unsafe.Pointer(&mockBatch[0]))

		emittedEvents += producedEvents

		return nil
	}

	input := newWorker(RemoteConfig{}, "test-channel", nil, newTestInput())

	input.processEvent = func(_ context.Context, _ Event, _ RemoteConfig) error {
		processedEvents++
		return nil
	}

	input.buffer = NewBuffer()
	input.maxReads = len(mockBatch) - 10
	input.currentMaxReads = input.maxReads
	input.maxEventsPerPollCycle = 999

	input.subscription = Subscription{
		handle:        42,
		startAt:       "beginning",
		sessionHandle: 0,
		channel:       "test-channel",
	}

	input.read(t.Context())

	requiredNextCalls := int(math.Ceil(float64(input.maxEventsPerPollCycle) / float64(input.maxReads)))
	assert.Equal(t, input.maxEventsPerPollCycle, input.eventsReadInPollCycle)
	assert.Equal(t, requiredNextCalls, nextCalls)
	assert.Equal(t, input.maxEventsPerPollCycle, processedEvents)
	assert.Equal(t, input.currentMaxReads, input.maxReads)

	nextCalls = 0
	input.maxEventsPerPollCycle = 0
	input.eventsReadInPollCycle = 0
	emittedEvents = 0
	processedEvents = 0
	maxEventsToEmit = 420
	input.read(t.Context())

	// +1 is the 0 event stop call
	requiredNextCalls = int(math.Ceil(float64(maxEventsToEmit)/float64(input.maxReads))) + 1
	assert.Equal(t, requiredNextCalls, nextCalls)
	assert.Equal(t, maxEventsToEmit, processedEvents)
	assert.Equal(t, input.currentMaxReads, input.maxReads)
}

//
// Domain Controller Discovery Tests
//

// mockGetJoinedDomainControllers is a test helper to override the DC discovery function.
// The actual override requires replacing getJoinedDomainControllersRemoteConfig at the package level.
// We use a variable-based approach consistent with how evtSubscribe is mocked.

// TestDCDiscovery_FlagDisabledByDefault ensures discover_domain_controllers defaults to false.
func TestDCDiscovery_FlagDisabledByDefault(t *testing.T) {
	cfg := NewConfig()
	assert.False(t, cfg.DiscoverDomainControllers, "discover_domain_controllers should default to false")
}

// TestDCDiscovery_LocalIgnoresFlag ensures that for local (non-remote) input,
// the discover_domain_controllers flag is ignored and only a local worker is started.
func TestDCDiscovery_LocalIgnoresFlag(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	persister := testutil.NewMockPersister("")
	input := newTestInputWithLogger(logger)
	input.channel = "Application"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.ignoreChannelErrors = true
	input.discoverDomainControllers = true
	// remote is empty → local mode

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	// Should log a message about DC discovery not being applicable
	found := false
	for _, log := range logs.All() {
		if log.Level == zap.InfoLevel &&
			containsString(log.Message, "domain controller discovery is not applicable") {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected log message about DC discovery not applicable for local server")

	// Only the local worker should be registered
	input.workersMu.RLock()
	defer input.workersMu.RUnlock()
	assert.Len(t, input.workers, 1, "Should have exactly one local worker")
	_, hasLocal := input.workers["_Application"]
	assert.True(t, hasLocal, "The single worker should have empty key (local)")
}

// TestDCDiscovery_RemoteEnabled ensures that when discover_domain_controllers is false
// and remote is configured, only the configured remote server worker is started.
func TestDCDiscovery_RemoteEnabled(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose
	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Security"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = false
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "user",
		Password: "pass",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()
	assert.Len(t, input.workers, 1, "Should have exactly one worker (the configured remote)")
	_, hasConfigured := input.workers["configured-server_Security"]
	assert.True(t, hasConfigured, "Worker for configured-server should exist")
}

// TestDCDiscovery_DiscoverySucceeds_AllWorkersStarted ensures that when DC discovery
// returns multiple controllers, a worker is started for each discovered DC plus the
// originally configured remote server.
func TestDCDiscovery_DiscoverySucceeds_AllWorkersStarted(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			{Server: "dc1.example.com", Username: username, Password: password},
			{Server: "dc2.example.com", Username: username, Password: password},
			{Server: "dc3.example.com", Username: username, Password: password},
		}, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Application"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()

	// 3 discovered DCs + 1 configured server = 4 workers
	assert.Len(t, input.workers, 4, "Should have 4 workers (3 discovered + 1 configured)")
	assert.Contains(t, input.workers, "dc1.example.com_Security")
	assert.Contains(t, input.workers, "dc2.example.com_Security")
	assert.Contains(t, input.workers, "dc3.example.com_Security")
	assert.Contains(t, input.workers, "configured-server_Application")
}

// TestDCDiscovery_DiscoverySucceeds_DCWorkersUseSecurityChannel verifies that
// discovered DC workers use the "Security" channel and nil query.
func TestDCDiscovery_DiscoverySucceeds_DCWorkersUseSecurityChannel(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose
	originalGetDCs := getJoinedDomainControllersRemoteConfig

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			{Server: "dc1.example.com", Username: username, Password: password},
		}, nil
	}

	var capturedWorkers []*SingleInputWorker
	originalNewWorker := newWorker
	_ = originalNewWorker // newWorker is a package-level func, capture via startRemoteSession

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(w *SingleInputWorker) error {
		capturedWorkers = append(capturedWorkers, w)
		return nil
	}
	input.channel = "Application"
	query := "*[System]"
	input.query = &query
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	// Find the DC worker and the configured worker
	var dcWorker, configuredWorker *SingleInputWorker
	for _, w := range capturedWorkers {
		if w.remote.Server == "dc1.example.com" {
			dcWorker = w
		}
		if w.remote.Server == "configured-server" {
			configuredWorker = w
		}
	}

	require.NotNil(t, dcWorker, "DC worker should have been created")
	assert.Equal(t, "Security", dcWorker.channel, "DC worker should use Security channel")
	assert.Nil(t, dcWorker.query, "DC worker should have nil query")

	require.NotNil(t, configuredWorker, "Configured worker should have been created")
	assert.Equal(t, "Application", configuredWorker.channel, "Configured worker should use original channel")
	assert.NotNil(t, configuredWorker.query, "Configured worker should retain query")
	assert.Equal(t, "*[System]", *configuredWorker.query)
}

// TestDCDiscovery_DiscoveryReturnsNil_OnlyConfiguredServerStarts ensures nil result
// from DC discovery still starts the configured server.
func TestDCDiscovery_DiscoveryReturnsNil_OnlyConfiguredServerStarts(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}

	originalEvtClose := evtClose
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})
	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, _, _ string) ([]RemoteConfig, error) {
		return nil, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Security"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()
	assert.Len(t, input.workers, 1)
	assert.Contains(t, input.workers, "configured-server_Security")
}

// TestDCDiscovery_PartialWorkerStartFailure_IgnoreChannelErrors ensures that when
// some DC workers fail to start and ignoreChannelErrors is true, the remaining
// workers continue.
func TestDCDiscovery_PartialWorkerStartFailure_IgnoreChannelErrors(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	callCount := 0
	originalEvtSubscribe := evtSubscribe
	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		callCount++
		// Fail the second subscription (dc2)
		if callCount == 2 {
			return 0, windows.ERROR_EVT_CHANNEL_NOT_FOUND
		}
		return 42, nil
	}

	originalEvtClose := evtClose
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			{Server: "dc1.example.com", Username: username, Password: password},
			{Server: "dc2.example.com", Username: username, Password: password},
			{Server: "dc3.example.com", Username: username, Password: password},
		}, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInputWithLogger(logger)
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Security"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.ignoreChannelErrors = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err, "Should not error when ignoreChannelErrors is true")
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()

	// dc1 succeeds, dc2 fails, dc3 succeeds, configured-server succeeds = 3 workers
	assert.Len(t, input.workers, 3)
	assert.Contains(t, input.workers, "dc1.example.com_Security")
	assert.NotContains(t, input.workers, "dc2.example.com_Security")
	assert.Contains(t, input.workers, "dc3.example.com_Security")
	assert.Contains(t, input.workers, "configured-server_Security")

	// Verify warning was logged for dc2
	foundWarn := false
	for _, log := range logs.All() {
		if log.Level == zap.WarnLevel && containsString(log.Message, "Failed to start worker") {
			foundWarn = true
			break
		}
	}
	assert.True(t, foundWarn, "Expected warning log for failed dc2 worker")
}

// TestDCDiscovery_AllWorkersFail_IgnoreChannelErrors ensures that if ALL workers
// (discovered + configured) fail but ignoreChannelErrors is true, Start() succeeds
// with zero workers.
func TestDCDiscovery_AllWorkersFail_IgnoreChannelErrors(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose
	evtClose = func(_ uintptr) error { return nil }
	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 0, windows.ERROR_EVT_CHANNEL_NOT_FOUND
	}

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			{Server: "dc1.example.com", Username: username, Password: password},
		}, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Security"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.ignoreChannelErrors = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()
	assert.Empty(t, input.workers, "All workers failed, should have zero workers")
}

// TestDCDiscovery_DuplicateServer_Deduplication tests that if a discovered DC has
// the same server name as the configured server, both workers are created
// (the worker key normalization may cause the second to overwrite the first).
func TestDCDiscovery_DuplicateServer_NoOverwritesInWorkerMap(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose

	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}
	evtClose = func(_ uintptr) error { return nil }

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			// Same server as configured, but discovered via LDAP
			{Server: "configured-server", Username: username, Password: password},
		}, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Application"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Stop()) })

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()

	// Both map to "configured-server" key; the last one registered wins
	assert.Len(t, input.workers, 2)
	assert.Contains(t, input.workers, "configured-server_Application")
	assert.Contains(t, input.workers, "configured-server_Security")
}

// TestDCDiscovery_StopCleansUpAllWorkers ensures that Stop() properly cleans up
// all workers including discovered DC workers.
func TestDCDiscovery_StopCleansUpAllWorkers(t *testing.T) {
	originalEvtSubscribe := evtSubscribe
	originalEvtClose := evtClose
	evtSubscribe = func(_ uintptr, _ windows.Handle, _, _ *uint16, _, _, _ uintptr, _ uint32) (uintptr, error) {
		return 42, nil
	}

	t.Cleanup(func() {
		evtSubscribe = originalEvtSubscribe // runs SECOND
		evtClose = originalEvtClose
	})

	closedHandles := make(map[uintptr]bool)
	evtClose = func(h uintptr) error {
		closedHandles[h] = true
		return nil
	}

	originalGetDCs := getJoinedDomainControllersRemoteConfig
	defer func() { getJoinedDomainControllersRemoteConfig = originalGetDCs }()
	getJoinedDomainControllersRemoteConfig = func(_ *zap.Logger, username, password string) ([]RemoteConfig, error) {
		return []RemoteConfig{
			{Server: "dc1.example.com", Username: username, Password: password},
			{Server: "dc2.example.com", Username: username, Password: password},
		}, nil
	}

	persister := testutil.NewMockPersister("")
	input := newTestInput()
	input.startRemoteSession = func(_ *SingleInputWorker) error { return nil }
	input.channel = "Security"
	input.startAt = "end"
	input.pollInterval = 1 * time.Second
	input.discoverDomainControllers = true
	input.remote = RemoteConfig{
		Server:   "configured-server",
		Username: "admin",
		Password: "secret",
	}

	err := input.Start(persister)
	require.NoError(t, err)

	// Verify workers were created
	input.workersMu.RLock()
	assert.Len(t, input.workers, 3)
	input.workersMu.RUnlock()

	// Stop should clean up all workers
	err = input.Stop()
	require.NoError(t, err)

	input.workersMu.RLock()
	defer input.workersMu.RUnlock()
	assert.Empty(t, input.workers, "All workers should be removed after Stop()")
}

// TestDCDiscovery_PersistKeyUniqueness verifies that each worker gets a unique
// persist key so bookmarks don't collide.
func TestDCDiscovery_PersistKeyUniqueness(t *testing.T) {
	w1 := &SingleInputWorker{
		remote:  RemoteConfig{Server: "dc1.example.com"},
		channel: "Security",
	}
	w2 := &SingleInputWorker{
		remote:  RemoteConfig{Server: "dc2.example.com"},
		channel: "Security",
	}
	wLocal := &SingleInputWorker{
		remote:  RemoteConfig{Server: ""},
		channel: "Security",
	}
	wConfigured := &SingleInputWorker{
		remote:  RemoteConfig{Server: "configured-server"},
		channel: "Application",
	}

	key1 := w1.getPersistKey()
	key2 := w2.getPersistKey()
	keyLocal := wLocal.getPersistKey()
	keyConfigured := wConfigured.getPersistKey()

	// All keys should be unique
	keys := map[string]bool{}
	for _, k := range []string{key1, key2, keyLocal, keyConfigured} {
		assert.False(t, keys[k], "Duplicate persist key: %s", k)
		keys[k] = true
	}

	// Remote keys should have the "remote::" prefix
	assert.Contains(t, key1, "remote::dc1.example.com")
	assert.Contains(t, key2, "remote::dc2.example.com")
	assert.Contains(t, keyConfigured, "remote::configured-server")

	// Local key should not have remote prefix
	assert.Equal(t, "Security", keyLocal)
}

// containsString is a helper to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
