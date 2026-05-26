package trustscore

import (
	"path"
	"strings"
)

var assetExtensions = map[string]bool{
	".css":   true,
	".js":    true,
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".svg":   true,
	".ico":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".mp4":   true,
	".webm":  true,
	".wav":   true,
	".mp3":   true,
	".pdf":   true,
	".webp":  true,
	".map":   true,
}

// IsAssetPath returns true if the path has a known static asset extension.
func IsAssetPath(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return assetExtensions[ext]
}
