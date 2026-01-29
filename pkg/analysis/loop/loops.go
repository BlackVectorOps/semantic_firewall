package loop

import (
	"fmt"
	"sort"

	"golang.org/x/tools/go/ssa"
)

type LoopInfo struct {
	Function *ssa.Function
	Loops    []*Loop
	LoopMap  map[*ssa.BasicBlock]*Loop
}

type Loop struct {
	Header     *ssa.BasicBlock
	Latch      *ssa.BasicBlock
	Blocks     map[*ssa.BasicBlock]bool
	Exits      []*ssa.BasicBlock
	Parent     *Loop
	Children   []*Loop
	Inductions map[*ssa.Phi]*InductionVariable
	TripCount  SCEV
	SCEVCache  map[ssa.Value]SCEV
}

func (l *Loop) String() string {
	return fmt.Sprintf("L_%s", l.Header.String())
}

type InductionVariable struct {
	Phi   *ssa.Phi
	Type  IVType
	Start SCEV
	Step  SCEV
}

type IVType int

const (
	IVTypeUnknown IVType = iota
	IVTypeBasic
	IVTypeDerived
	IVTypeGeometric
	IVTypePolynomial
)

func DetectLoops(fn *ssa.Function) *LoopInfo {
	_ = fn.DomPreorder()
	info := &LoopInfo{
		Function: fn,
		LoopMap:  make(map[*ssa.BasicBlock]*Loop),
	}

	if len(fn.Blocks) == 0 {
		return info
	}

	headerToLatches := make(map[*ssa.BasicBlock][]*ssa.BasicBlock)
	var headers []*ssa.BasicBlock

	for _, b := range fn.Blocks {
		for _, succ := range b.Succs {
			if succ == fn.Recover {
				continue
			}
			if succ.Dominates(b) {
				if _, exists := headerToLatches[succ]; !exists {
					headers = append(headers, succ)
				}
				headerToLatches[succ] = append(headerToLatches[succ], b)
			}
		}
	}

	sort.Slice(headers, func(i, j int) bool { return headers[i].Index < headers[j].Index })

	var allLoops []*Loop

	for _, header := range headers {
		latches := headerToLatches[header]
		loop := &Loop{
			Header:     header,
			Latch:      latches[0],
			Blocks:     make(map[*ssa.BasicBlock]bool),
			Inductions: make(map[*ssa.Phi]*InductionVariable),
			Children:   make([]*Loop, 0),
			SCEVCache:  make(map[ssa.Value]SCEV),
		}

		constructLoopBody(loop, latches)

		for b := range loop.Blocks {
			for _, succ := range b.Succs {
				if !loop.Blocks[succ] {
					loop.Exits = append(loop.Exits, b)
					break
				}
			}
		}

		sort.Slice(loop.Exits, func(i, j int) bool {
			return loop.Exits[i].Index < loop.Exits[j].Index
		})

		allLoops = append(allLoops, loop)
		info.LoopMap[header] = loop
	}

	for _, child := range allLoops {
		var bestParent *Loop
		bestSize := int(^uint(0) >> 1)

		for _, candidate := range allLoops {
			if child == candidate {
				continue
			}
			if candidate.Blocks[child.Header] {
				size := len(candidate.Blocks)
				if size < bestSize {
					bestSize = size
					bestParent = candidate
				}
			}
		}

		if bestParent != nil {
			child.Parent = bestParent
			bestParent.Children = append(bestParent.Children, child)
		} else {
			info.Loops = append(info.Loops, child)
		}
	}

	return info
}

func constructLoopBody(loop *Loop, latches []*ssa.BasicBlock) {
	loop.Blocks[loop.Header] = true
	var worklist []*ssa.BasicBlock
	for _, l := range latches {
		loop.Blocks[l] = true
		worklist = append(worklist, l)
	}

	for len(worklist) > 0 {
		curr := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		if curr == loop.Header {
			continue
		}

		for _, pred := range curr.Preds {
			if !loop.Blocks[pred] {
				loop.Blocks[pred] = true
				worklist = append(worklist, pred)
			}
		}
	}
}

func CountLoops(loops []*Loop) int {
	count := 0
	stack := make([]*Loop, len(loops))
	copy(stack, loops)

	for len(stack) > 0 {
		l := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		count++
		if len(l.Children) > 0 {
			stack = append(stack, l.Children...)
		}
	}
	return count
}
