// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitoring

import (
	"context"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"fmt"

	"istio.io/istio/galley/pkg/runtime/log"
	"istio.io/istio/galley/pkg/runtime/resource"
)

const (
	collection = "collection"
	namespace  = "namespace"
	name       = "name"
)

var (
	// CollectionTag holds the type URL for the context.
	CollectionTag tag.Key
	// NamespaceTag holds namespace of the resource for the context.
	NamespaceTag tag.Key
	// NameTag holds name of the resource for the context.
	NameTag tag.Key
)

var (
	strategyOnChangeTotal = stats.Int64(
		"galley/runtime/strategy/on_change_total",
		"The number of times the strategy's onChange has been called",
		stats.UnitDimensionless)
	strategyOnTimerMaxTimeReachedTotal = stats.Int64(
		"galley/runtime/strategy/timer_max_time_reached_total",
		"The number of times the max time has been reached",
		stats.UnitDimensionless)
	strategyOnTimerQuiesceReachedTotal = stats.Int64(
		"galley/runtime/strategy/timer_quiesce_reached_total",
		"The number of times a quiesce has been reached",
		stats.UnitDimensionless)
	strategyOnTimerResetTotal = stats.Int64(
		"galley/runtime/strategy/timer_resets_total",
		"The number of times the timer has been reset",
		stats.UnitDimensionless)
	processorEventSpansMs = stats.Int64(
		"galley/runtime/processor/event_span_duration_milliseconds",
		"The duration between each incoming event",
		stats.UnitMilliseconds)
	processorEventsProcessed = stats.Int64(
		"galley/runtime/processor/events_processed_total",
		"The number of events that have been processed",
		stats.UnitDimensionless)
	processorSnapshotsPublished = stats.Int64(
		"galley/runtime/processor/snapshots_published_total",
		"The number of snapshots that have been published",
		stats.UnitDimensionless)
	processorEventsPerSnapshot = stats.Int64(
		"galley/runtime/processor/snapshot_events_total",
		"The number of events per snapshot",
		stats.UnitDimensionless)
	processorSnapshotLifetimesMs = stats.Int64(
		"galley/runtime/processor/snapshot_lifetime_duration_milliseconds",
		"The duration of each snapshot",
		stats.UnitMilliseconds)
	stateTypeInstancesTotal = stats.Int64(
		"galley/runtime/state/type_instances_total",
		"The number of type instances per type URL",
		stats.UnitDimensionless)

	durationDistributionMs = view.Distribution(0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8193, 16384, 32768, 65536,
		131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608)

	stateTypeConfigTotal map[string]*stats.Int64Measure
)

// RecordStrategyOnChange
func RecordStrategyOnChange() {
	stats.Record(context.Background(), strategyOnChangeTotal.M(1))
}

// RecordOnTimer
func RecordOnTimer(maxTimeReached, quiesceTimeReached, timerReset bool) {
	if maxTimeReached {
		stats.Record(context.Background(), strategyOnTimerMaxTimeReachedTotal.M(1))
	}
	if quiesceTimeReached {
		stats.Record(context.Background(), strategyOnTimerQuiesceReachedTotal.M(1))
	}
	if timerReset {
		stats.Record(context.Background(), strategyOnTimerResetTotal.M(1))
	}
}

// RecordProcessorEventProcessed
func RecordProcessorEventProcessed(eventSpan time.Duration) {
	stats.Record(context.Background(), processorEventsProcessed.M(1),
		processorEventSpansMs.M(eventSpan.Nanoseconds()/1e6))
}

// RecordProcessorSnapshotPublished
func RecordProcessorSnapshotPublished(events int64, snapshotSpan time.Duration) {
	stats.Record(context.Background(), processorSnapshotsPublished.M(1))
	stats.Record(context.Background(), processorEventsPerSnapshot.M(events),
		processorSnapshotLifetimesMs.M(snapshotSpan.Nanoseconds()/1e6))
}

// RecordStateTypeCount
func RecordStateTypeCount(collection string, count int) {
	ctx, err := tag.New(context.Background(), tag.Insert(CollectionTag, collection))
	if err != nil {
		log.Scope.Errorf("Error creating monitoring context for counting state: %v", err)
	} else {
		RecordStateTypeCountWithContext(ctx, count)
	}
}

// RecordStateTypeCountWithContext
func RecordStateTypeCountWithContext(ctx context.Context, count int) {
	if ctx != nil {
		stats.Record(ctx, stateTypeInstancesTotal.M(int64(count)))
	}
}

// RecordDetailedStateType
func RecordDetailedStateType(namespace, name string, collection resource.Collection, count int) {
	ctx, err := tag.New(context.Background(), tag.Insert(NamespaceTag, namespace),
		tag.Insert(NameTag, name))
	if err != nil {
		log.Scope.Errorf("Error creating monitoring context for counting state: %v", err)
	} else {
		RecordDetailedStateTypeWithContext(ctx, collection, count)
	}
}

// RecordDetailedStateTypeWithContext
func RecordDetailedStateTypeWithContext(ctx context.Context, collection resource.Collection, count int) {
	if ctx == nil {
		return
	}
	if stateTypeConfigTotal[collection.String()] == nil {
		err := registerNewStateTypeConfigView(collection)
		if err != nil {
			log.Scope.Errorf("Could not register collection %v for monitoring", err)
			return
		}
	}
	stats.Record(ctx, stateTypeConfigTotal[collection.String()].M(int64(count)))
}

func newView(measure stats.Measure, keys []tag.Key, aggregation *view.Aggregation) *view.View {
	return &view.View{
		Name:        measure.Name(),
		Description: measure.Description(),
		Measure:     measure,
		TagKeys:     keys,
		Aggregation: aggregation,
	}
}

func getStateTypeConfigKeys() ([]tag.Key, error) {
	var err error
	if NamespaceTag, err = tag.NewKey(namespace); err != nil {
		panic(err)
	}
	if NameTag, err = tag.NewKey(name); err != nil {
		panic(err)
	}

	return []tag.Key{NamespaceTag, NameTag}, err
}

func registerNewStateTypeConfigView(collection resource.Collection) error {
	collectionStr := collection.String()
	stateTypeConfigTotal[collection.String()] = stats.Int64(fmt.Sprintf("galley/runtime/state/%s", collectionStr),
		fmt.Sprintf("The number of valid %s known to galley at a point in time", collectionStr),
		stats.UnitDimensionless)
	nameKeys, err := getStateTypeConfigKeys()
	if err != nil {
		return err
	}
	err = view.Register(
		newView(stateTypeConfigTotal[collectionStr], nameKeys, view.LastValue()),
	)
	return err
}

func init() {
	var err error
	if CollectionTag, err = tag.NewKey(collection); err != nil {
		panic(err)
	}

	var noKeys []tag.Key
	collectionKeys := []tag.Key{CollectionTag}

	err = view.Register(
		newView(strategyOnTimerResetTotal, noKeys, view.Count()),
		newView(strategyOnChangeTotal, noKeys, view.Count()),
		newView(strategyOnTimerMaxTimeReachedTotal, noKeys, view.Count()),
		newView(strategyOnTimerQuiesceReachedTotal, noKeys, view.Count()),
		newView(processorEventSpansMs, noKeys, durationDistributionMs),
		newView(processorEventsProcessed, noKeys, view.Count()),
		newView(processorSnapshotsPublished, noKeys, view.Count()),
		newView(processorEventsPerSnapshot, noKeys, view.Distribution(0, 1, 2, 4, 8, 16, 32, 64, 128, 256)),
		newView(processorSnapshotLifetimesMs, noKeys, durationDistributionMs),
		newView(stateTypeInstancesTotal, collectionKeys, view.LastValue()),
	)

	if err != nil {
		panic(err)
	}
	stateTypeConfigTotal = make(map[string]*stats.Int64Measure)
}
