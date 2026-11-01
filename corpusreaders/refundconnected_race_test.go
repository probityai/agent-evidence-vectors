//go:build race

package corpora

// rcDiffStride is how many mutations apart the differential replays under the race
// detector, which makes the readers about forty times slower; the run without it
// replays every mutation and requires every skipped rule to be noticed.
const rcDiffStride = 64
