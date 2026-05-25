package main

import (
	"encoding/json"
	"math"
	"os"
	"strings"
)

type TfidfVectorizer struct {
	Vocabulary map[string]int
	IDF        []float64
	NgramMin   int
	NgramMax   int
	NumCols    int
}

// LoadTfidf reads the exported TF-IDF JSON assets
func LoadTfidf(path string) (*TfidfVectorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Vocabulary map[string]int `json:"vocabulary"`
		IDF        []float64      `json:"idf"`
		NgramMin   int            `json:"ngram_min"`
		NgramMax   int            `json:"ngram_max"`
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	return &TfidfVectorizer{
		Vocabulary: parsed.Vocabulary,
		IDF:        parsed.IDF,
		NgramMin:   parsed.NgramMin,
		NgramMax:   parsed.NgramMax,
		NumCols:    len(parsed.IDF),
	}, nil
}

// Transform converts the input text into a TF-IDF feature slice (L2 normalized)
func (v *TfidfVectorizer) Transform(text string) []float64 {
	// Scikit-Learn's TfidfVectorizer lowercases by default
	text = strings.ToLower(text)
	
	// Character ngrams in python operate on Unicode points (runes in Go)
	runes := []rune(text)
	n := len(runes)

	// Step 1: Count term frequencies
	tf := make(map[int]float64)
	for length := v.NgramMin; length <= v.NgramMax; length++ {
		for i := 0; i <= n-length; i++ {
			ngram := string(runes[i : i+length])
			if idx, ok := v.Vocabulary[ngram]; ok {
				tf[idx] += 1.0
			}
		}
	}

	// Step 2: Apply IDF weighting and compute L2 norm
	vec := make([]float64, v.NumCols)
	var sumSq float64
	for idx, count := range tf {
		// Scikit-Learn default: TF is just raw count (sublinear_tf=False)
		val := count * v.IDF[idx]
		vec[idx] = val
		sumSq += val * val
	}

	// Step 3: L2 Normalize
	if sumSq > 0 {
		norm := math.Sqrt(sumSq)
		for idx := range tf {
			vec[idx] /= norm
		}
	}

	return vec
}
