/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dbus

import (
	"fmt"
	"sync"

	godbus "github.com/godbus/dbus"
)

// Fake is a simple fake Interface type.
type Fake struct {
	systemBus  *FakeConnection
	sessionBus *FakeConnection
}

// FakeConnection represents a fake D-Bus connection
type FakeConnection struct {
	lock           sync.Mutex
	busObject      *fakeObject
	objects        map[string]*fakeObject
	signalHandlers []chan<- *godbus.Signal
}

// FakeHandler is used to handle fake D-Bus method calls
type FakeHandler func(method string, args ...interface{}) ([]interface{}, error)

type fakeObject struct {
	handler FakeHandler
}

type fakeCall struct {
	ret []interface{}
	err error
}

// NewFake returns a new Interface which will fake talking to D-Bus
func NewFake(systemBus *FakeConnection, sessionBus *FakeConnection) *Fake {
	return &Fake{systemBus, sessionBus}
}

// NewFakeConnection returns a FakeConnection Interface
func NewFakeConnection() *FakeConnection {
	return &FakeConnection{
		objects: make(map[string]*fakeObject),
	}
}

// SystemBus is part of Interface
func (db *Fake) SystemBus() (Connection, error) {
	if db.systemBus != nil {
		return db.systemBus, nil
	}
	return nil, fmt.Errorf("DBus is not running")
}

// SessionBus is part of Interface
func (db *Fake) SessionBus() (Connection, error) {
	if db.sessionBus != nil {
		return db.sessionBus, nil
	}
	return nil, fmt.Errorf("DBus is not running")
}

// BusObject is part of the Connection interface
func (conn *FakeConnection) BusObject() Object {
	return conn.busObject
}

// Object is part of the Connection interface
func (conn *FakeConnection) Object(name, path string) Object {
	return conn.objects[name+path]
}

// Signal is part of the Connection interface
func (conn *FakeConnection) Signal(ch chan<- *godbus.Signal) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	for i := range conn.signalHandlers {
		if conn.signalHandlers[i] == ch {
			conn.signalHandlers = append(conn.signalHandlers[:i], conn.signalHandlers[i+1:]...)
			return
		}
	}
	conn.signalHandlers = append(conn.signalHandlers, ch)
}

// SetBusObject sets the handler for the BusObject of conn
func (conn *FakeConnection) SetBusObject(handler FakeHandler) {
	conn.busObject = &fakeObject{handler}
}

// AddObject adds a handler for the Object at name and path
func (conn *FakeConnection) AddObject(name, path string, handler FakeHandler) {
	conn.objects[name+path] = &fakeObject{handler}
}

// EmitSignal emits a signal on conn
func (conn *FakeConnection) EmitSignal(name, path, iface, signal string, args ...interface{}) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	sig := &godbus.Signal{
		Sender: name,
		Path:   godbus.ObjectPath(path),
		Name:   iface + "." + signal,
		Body:   args,
	}
	for _, ch := range conn.signalHandlers {
		ch <- sig
	}
}

// Call is part of the Object interface
func (obj *fakeObject) Call(method string, flags godbus.Flags, args ...interface{}) Call {
	ret, err := obj.handler(method, args...)
	return &fakeCall{ret, err}
}

// Store is part of the Call interface
func (call *fakeCall) Store(retvalues ...interface{}) error {
	if call.err != nil {
		return call.err
	}
	return godbus.Store(call.ret, retvalues...)
}
