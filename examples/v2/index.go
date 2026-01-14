package main

func sum(items []int) int {
	total := 0
	for i := 0; i < len(items); i++ {
		total += items[i]
	}
	return total
}

func main() {
	_ = sum // example function, not meant to be executed
}
