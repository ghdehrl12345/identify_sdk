package log

import (
	"time"
)

// Metrics holds performance measurements.
type Metrics struct {
	ProofGenerationTime time.Duration
	VerificationTime    time.Duration
	CommitmentTime      time.Duration
	KeyLoadTime         time.Duration
}

// Timer helps measure operation duration.
type Timer struct {
	start time.Time
}

// Start creates a new timer.
func Start() *Timer {
	return &Timer{start: time.Now()}
}

// Elapsed returns the time elapsed since start.
func (t *Timer) Elapsed() time.Duration {
	return time.Since(t.start)
}

// Stop logs the elapsed time and returns it.
func (t *Timer) Stop(operation string) time.Duration {
	elapsed := t.Elapsed()
	Debug("operation completed", String("operation", operation), Duration("elapsed", elapsed))
	return elapsed
}

// MeasureFunc measures the execution time of a function.
func MeasureFunc(operation string, fn func()) time.Duration {
	timer := Start()
	fn()
	return timer.Stop(operation)
}

// MeasureProofGeneration measures proof generation time.
func MeasureProofGeneration(fn func()) *Metrics {
	m := &Metrics{}
	m.ProofGenerationTime = MeasureFunc("proof_generation", fn)
	return m
}

// MeasureVerification measures verification time.
func MeasureVerification(fn func()) *Metrics {
	m := &Metrics{}
	m.VerificationTime = MeasureFunc("verification", fn)
	return m
}
