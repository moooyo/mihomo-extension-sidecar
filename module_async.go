package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const (
	// A script may hold at most this many live timers at once. The action
	// deadline still bounds total wall-clock time; this only stops a script
	// from allocating unbounded timer state inside that window.
	maxAsyncTimers = 64
	// Callbacks queued from worker goroutines. Reaching the cap applies
	// backpressure to the workers rather than growing without bound.
	asyncCallbackQueueCap = 256
)

// asyncLoop serializes callbacks produced by Go-side asynchronous work back
// onto the goroutine that owns the goja Runtime. goja is not goroutine-safe,
// so a worker goroutine never touches the VM: it posts a closure here and the
// owning goroutine runs it between microtask drains.
//
// Calling a promise resolve function re-enters the VM, and goja drains its
// microtask queue whenever control leaves the runtime, so a posted callback
// that resolves a promise also runs every reaction it unblocks.
type asyncLoop struct {
	callbacks chan func() error
	done      chan struct{}
	closeOnce sync.Once

	mu     sync.Mutex
	timers map[int64]*time.Timer
	nextID int64
}

func newAsyncLoop() *asyncLoop {
	return &asyncLoop{
		callbacks: make(chan func() error, asyncCallbackQueueCap),
		done:      make(chan struct{}),
		timers:    make(map[int64]*time.Timer),
	}
}

// post hands fn to the owning goroutine. It is safe to call from any goroutine
// and never blocks after close, so a worker that finishes once its action has
// already ended is discarded instead of leaking.
func (l *asyncLoop) post(fn func() error) {
	select {
	case <-l.done:
		return
	default:
	}
	select {
	case l.callbacks <- fn:
	case <-l.done:
	}
}

// close releases the loop. Pending timers are stopped and later posts are
// dropped, because their VM is gone by then.
func (l *asyncLoop) close() {
	l.closeOnce.Do(func() {
		close(l.done)
		l.mu.Lock()
		for _, timer := range l.timers {
			timer.Stop()
		}
		l.timers = nil
		l.mu.Unlock()
	})
}

// wait runs queued callbacks on the calling goroutine until settled reports
// completion or the action context ends. A callback error is uncatchable —
// an interrupt or stack overflow — so it stops the loop instead of being
// reported to the script.
func (l *asyncLoop) wait(ctx context.Context, settled func() bool) error {
	for !settled() {
		select {
		case fn := <-l.callbacks:
			if err := fn(); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// installTimerAPI exposes setTimeout/clearTimeout. The upstream proxy-client
// bundles use them only to race a pending request against a timeout. A delay
// longer than the action deadline is left alone rather than clamped: shortening
// it would fire the script's own timeout branch early and report a request
// timeout that never happened, while the action deadline already bounds the
// real wall-clock cost.
func (l *asyncLoop) installTimerAPI(vm *goja.Runtime) error {
	setTimeout := func(call goja.FunctionCall) goja.Value {
		callback, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			panic(vm.NewTypeError("setTimeout requires a function"))
		}
		delay := call.Argument(1).ToFloat()
		if !(delay > 0) {
			delay = 0
		}
		// Extra arguments are forwarded, matching the browser and Node shape
		// the bundles are written against.
		var extra []goja.Value
		if len(call.Arguments) > 2 {
			extra = append(extra, call.Arguments[2:]...)
		}

		l.mu.Lock()
		if l.timers == nil {
			l.mu.Unlock()
			return goja.Undefined()
		}
		if len(l.timers) >= maxAsyncTimers {
			l.mu.Unlock()
			panic(vm.NewGoError(fmt.Errorf("at most %d pending timers are allowed", maxAsyncTimers)))
		}
		l.nextID++
		id := l.nextID
		timer := time.AfterFunc(time.Duration(delay)*time.Millisecond, func() {
			l.post(func() error {
				l.forgetTimer(id)
				_, err := callback(goja.Undefined(), extra...)
				return err
			})
		})
		l.timers[id] = timer
		l.mu.Unlock()
		return vm.ToValue(id)
	}
	clearTimeout := func(call goja.FunctionCall) goja.Value {
		id := call.Argument(0).ToInteger()
		l.mu.Lock()
		if timer, exists := l.timers[id]; exists {
			timer.Stop()
			delete(l.timers, id)
		}
		l.mu.Unlock()
		return goja.Undefined()
	}
	if err := vm.Set("setTimeout", setTimeout); err != nil {
		return err
	}
	if err := vm.Set("clearTimeout", clearTimeout); err != nil {
		return err
	}
	// The bundles treat the interval pair as interchangeable with the timeout
	// pair for their one-shot timeout races; a repeating scheduler is not
	// exposed, so setInterval fires once and clearInterval cancels it.
	if err := vm.Set("setInterval", setTimeout); err != nil {
		return err
	}
	return vm.Set("clearInterval", clearTimeout)
}

func (l *asyncLoop) forgetTimer(id int64) {
	l.mu.Lock()
	if l.timers != nil {
		delete(l.timers, id)
	}
	l.mu.Unlock()
}

// promiseValue reports whether value is a Promise without deep-exporting it.
// A plain result object would otherwise be converted to Go twice, once here and
// once when the patch is parsed.
func promiseValue(vm *goja.Runtime, value goja.Value) (*goja.Promise, bool) {
	object, ok := value.(*goja.Object)
	if !ok {
		return nil, false
	}
	constructor, ok := vm.Get("Promise").(*goja.Object)
	if !ok || !vm.InstanceOf(object, constructor) {
		return nil, false
	}
	promise, ok := object.Export().(*goja.Promise)
	return promise, ok
}

// settlePromise drives a promise returned by a script entry point to
// completion. A non-promise value is returned unchanged, so a synchronous
// script keeps its exact previous behavior and cost.
func settlePromise(ctx context.Context, vm *goja.Runtime, loop *asyncLoop, value goja.Value) (goja.Value, error) {
	if value == nil {
		return value, nil
	}
	promise, ok := promiseValue(vm, value)
	if !ok {
		return value, nil
	}
	if err := loop.wait(ctx, func() bool { return promise.State() != goja.PromiseStatePending }); err != nil {
		return nil, err
	}
	if promise.State() == goja.PromiseStateRejected {
		return nil, promiseRejectionError(vm, promise.Result())
	}
	return promise.Result(), nil
}

// promiseRejectionError converts a rejection reason into a Go error, keeping an
// Error's stack when the script rejected with one.
func promiseRejectionError(vm *goja.Runtime, reason goja.Value) error {
	if reason == nil || goja.IsUndefined(reason) || goja.IsNull(reason) {
		return errors.New("script promise was rejected")
	}
	if object, ok := reason.(*goja.Object); ok {
		if stack := object.Get("stack"); stack != nil && !goja.IsUndefined(stack) && !goja.IsNull(stack) {
			return fmt.Errorf("script promise was rejected: %s", stack.String())
		}
	}
	return fmt.Errorf("script promise was rejected: %s", reason.String())
}
