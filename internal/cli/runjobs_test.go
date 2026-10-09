package cli

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRunJobs(t *testing.T) {
	for _, parallel := range []bool{true, false} {
		var running, peak, done atomic.Int32
		job := func() {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			running.Add(-1)
			done.Add(1)
		}
		runJobs(parallel, []func(){job, job, job})

		if done.Load() != 3 {
			t.Fatalf("parallel=%v: %d of 3 jobs finished before runJobs returned", parallel, done.Load())
		}
		if parallel && peak.Load() < 2 {
			t.Errorf("parallel jobs never overlapped (peak %d)", peak.Load())
		}
		if !parallel && peak.Load() != 1 {
			t.Errorf("sequential jobs overlapped (peak %d)", peak.Load())
		}
	}
}
