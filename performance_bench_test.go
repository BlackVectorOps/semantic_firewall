package semanticfw

import (
	"testing"
)

// BenchmarkEntropyCalculation measures the performance of entropy calculation
// using the optimized array-based approach vs the original map-based approach.
func BenchmarkEntropyCalculation(b *testing.B) {
	// Test data: typical code with mixed entropy
	testData := []byte(`package main
import "fmt"
func main() {
	data := []byte("Hello, World! This is a test string with some randomness: 0x4f3a2b1c")
	for i := 0; i < len(data); i++ {
		fmt.Printf("%x ", data[i])
	}
}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateEntropy(testData)
	}
}

// BenchmarkEntropyCalculation_LargeInput tests with larger input
func BenchmarkEntropyCalculation_LargeInput(b *testing.B) {
	// 10KB of mixed data
	testData := make([]byte, 10240)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateEntropy(testData)
	}
}

// BenchmarkMapSimilarity measures the performance of the optimized map similarity function
func BenchmarkMapSimilarity(b *testing.B) {
	mapA := map[string]int{
		"net.Dial":     2,
		"os.Exec":      1,
		"fmt.Println":  3,
		"time.Sleep":   1,
		"io.Copy":      2,
		"http.Get":     1,
		"json.Marshal": 2,
	}
	mapB := map[string]int{
		"net.Dial":    2,
		"os.Exec":     1,
		"fmt.Printf":  3,
		"time.After":  1,
		"io.Copy":     2,
		"http.Post":   1,
		"json.Decode": 2,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mapSimilarity(mapA, mapB)
	}
}

// BenchmarkTopologyExtraction measures topology extraction performance
func BenchmarkTopologyExtraction(b *testing.B) {
	src := `package semanticfw
import (
	"fmt"
	"net"
	"time"
)

func processData(input []byte) error {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return err
	}
	defer conn.Close()
	
	for i := 0; i < len(input); i++ {
		if _, err := conn.Write([]byte{input[i]}); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	fmt.Println("Data sent successfully")
	return nil
}
`

	results, err := FingerprintSource("bench.go", src, DefaultLiteralPolicy)
	if err != nil {
		b.Fatal(err)
	}
	if len(results) == 0 {
		b.Fatal("no functions found")
	}

	fn := results[0].GetSSAFunction()
	if fn == nil {
		b.Fatal("nil function")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractTopology(fn)
	}
}

// BenchmarkCanonicalization measures full canonicalization performance
func BenchmarkCanonicalization(b *testing.B) {
	src := `package semanticfw

func sum(items []int) int {
	total := 0
	for i := 0; i < len(items); i++ {
		total += items[i]
	}
	return total
}
`

	results, err := FingerprintSource("bench.go", src, DefaultLiteralPolicy)
	if err != nil {
		b.Fatal(err)
	}
	if len(results) == 0 {
		b.Fatal("no functions found")
	}

	fn := results[0].GetSSAFunction()
	if fn == nil {
		b.Fatal("nil function")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		canon := AcquireCanonicalizer(DefaultLiteralPolicy)
		_ = canon.CanonicalizeFunction(fn)
		ReleaseCanonicalizer(canon)
	}
}
