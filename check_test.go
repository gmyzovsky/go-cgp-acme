package main

import (
	"testing"
	"time"
)

func TestRenewalThreshold(t *testing.T) {
	nb := time.Now()
	const day = 24 * time.Hour
	const third = 1.0 / 3.0

	cases := []struct {
		name     string
		lifetime time.Duration
		fraction float64
		floor    time.Duration
		want     time.Duration
	}{
		{"90d fraction", 90 * day, third, 0, 30 * day},
		{"45d fraction", 45 * day, third, 0, 15 * day},
		{"6d shortlived", 6 * day, third, 0, 2 * day},
		{"floor wins on 2d cert", 2 * day, third, day, day},
		{"fraction wins over small floor", 90 * day, third, day, 30 * day},
		{"fraction disabled uses floor", 90 * day, 0, 720 * time.Hour, 720 * time.Hour},
	}
	for _, tc := range cases {
		got := renewalThreshold(nb, nb.Add(tc.lifetime), tc.fraction, tc.floor)
		// The fraction arithmetic is float-based, so allow a small delta.
		if d := got - tc.want; d < -time.Minute || d > time.Minute {
			t.Errorf("%s: threshold %s, want ~%s", tc.name, got, tc.want)
		}
	}
}
