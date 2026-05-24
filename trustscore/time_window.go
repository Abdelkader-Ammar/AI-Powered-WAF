package trustscore

import "math"

func slidingWindowCount(timestamps []float64, windowSeconds float64, now float64) int {
	count := 0
	for _, t := range timestamps {
		if now-t <= windowSeconds {
			count++
		}
	}
	return count
}

func slidingWindowRate(timestamps []float64, windowSeconds float64, now float64) float64 {
	count := slidingWindowCount(timestamps, windowSeconds, now)
	if windowSeconds == 0 {
		return 0
	}
	return float64(count) / windowSeconds
}

func interArrivalStats(timestamps []float64) (float64, float64) {
	if len(timestamps) < 3 {
		return 0.0, 0.0
	}

	var sorted []float64
	sorted = append(sorted, timestamps...)
	quickSort(sorted)

	var intervals []float64
	for i := 0; i < len(sorted)-1; i++ {
		intervals = append(intervals, sorted[i+1]-sorted[i])
	}

	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, v := range intervals {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(intervals))

	return mean, math.Sqrt(variance)
}

func coefficientOfVariation(timestamps []float64) float64 {
	mean, stddev := interArrivalStats(timestamps)
	if mean == 0 {
		return 0.0
	}
	return stddev / mean
}

func quickSort(arr []float64) {
	if len(arr) <= 1 {
		return
	}
	quickSortHelper(arr, 0, len(arr)-1)
}

func quickSortHelper(arr []float64, low, high int) {
	if low < high {
		pi := partition(arr, low, high)
		quickSortHelper(arr, low, pi-1)
		quickSortHelper(arr, pi+1, high)
	}
}

func partition(arr []float64, low, high int) int {
	pivot := arr[high]
	i := low - 1
	for j := low; j < high; j++ {
		if arr[j] < pivot {
			i++
			arr[i], arr[j] = arr[j], arr[i]
		}
	}
	arr[i+1], arr[high] = arr[high], arr[i+1]
	return i + 1
}
