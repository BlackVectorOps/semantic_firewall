package main

func sum(items []int) int {
	total := 0
	for _, x := range items {
		total += x
	}
	return total
}

func main() {
	_ = sum // example function, not meant to be executed
}
