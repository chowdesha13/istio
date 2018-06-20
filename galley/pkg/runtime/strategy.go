//  Copyright 2018 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package runtime

import (
	"sync"
	"time"
)

const (
	// Maximum wait time before deciding to publish the events.
	defaultMaxWaitDuration = time.Minute

	// Minimum time distance between two events for deciding on the quiesce point. If the time delay
	// between two events is larger than this, then we can deduce that we hit a quiesce point.
	defaultQuiesceDuration = time.Second * 5

	// The frequency for firing the timer events.
	defaultTimerFrequency = time.Second
)

// publishingStrategy is a heuristic model for deciding when to publish snapshots. It tries to detect
// quiesce points for events with a total bounded wait time.
type publishingStrategy struct {
	maxWaitDuration time.Duration
	quiesceDuration time.Duration
	timerFrequency  time.Duration

	lock sync.Mutex

	// publish channel is used to trigger the publication of snapshots.
	publish chan struct{}

	// the time of first event that is received.
	firstEvent time.Time

	// the time of the latest event that is received.
	latestEvent time.Time

	// timer that is used for periodically checking for the quiesce point.
	timer *time.Timer

	// nowFn is a testing hook for overriding time.Now()
	nowFn func() time.Time

	// afterFuncFn is a testing hook for overriding time.AfterFunc()
	afterFuncFn func(time.Duration, func()) *time.Timer
}

func newPublishingStrategyWithDefaults() *publishingStrategy {
	return newPublishingStrategy(defaultMaxWaitDuration, defaultQuiesceDuration, defaultTimerFrequency)
}

func newPublishingStrategy(
	maxWaitDuration time.Duration,
	quiesceDuration time.Duration,
	timerFrequency time.Duration) *publishingStrategy {

	return &publishingStrategy{
		maxWaitDuration: maxWaitDuration,
		quiesceDuration: quiesceDuration,
		timerFrequency:  timerFrequency,
		publish:         make(chan struct{}, 1),
		nowFn:           time.Now,
		afterFuncFn:     time.AfterFunc,
	}
}

func (s *publishingStrategy) onChange() {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Capture the latest event time.
	s.latestEvent = s.nowFn()
	if s.timer == nil {
		// If this is the first event after a quiesce, start a timer to periodically check event
		// frequency and fire the publish event.
		s.firstEvent = s.latestEvent
		s.timer = s.afterFuncFn(s.timerFrequency, s.onTimer)
	}
}

func (s *publishingStrategy) onTimer() {
	s.lock.Lock()
	defer s.lock.Unlock()

	now := s.nowFn()

	// If there has been a long time since the first event, or if there was a quiesce since last event,
	// then fire publish to create new snapshots.
	// Otherwise, reset the timer and get a call again.
	maxTimeReached := s.firstEvent.Add(s.maxWaitDuration).Before(now)
	quiesceReached := s.latestEvent.Add(s.quiesceDuration).Before(now)

	if maxTimeReached || quiesceReached {
		s.timer.Stop()
		s.timer = nil
		s.publish <- struct{}{}
	} else {
		s.timer.Reset(s.timerFrequency)
	}
}

func (s *publishingStrategy) reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}
