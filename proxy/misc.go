package proxy

import "sync"

var PanicCheckFunc func()

func PanicCheck() {
	if PanicCheckFunc != nil {
		PanicCheckFunc()
	}
}

// FIFO slice queue thing

type FifoQueue[T any] struct {
	items []T
	mutex sync.Mutex
}

func NewFifoQueue[T any]() *FifoQueue[T] {
	return &FifoQueue[T]{items: make([]T, 0)}
}

func (q *FifoQueue[T]) Push(item T) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.items = append(q.items, item)
}

func (q *FifoQueue[T]) Pop() (T, bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if len(q.items) == 0 {
		var zero T
		return zero, false
	}

	item := q.items[0]
	q.items = q.items[1:]
	return item, true
}

func (q *FifoQueue[T]) Len() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	return len(q.items)
}

// Utils

func findIdx[T comparable](slice []T, element T) int {
	for i, v := range slice {
		if v == element {
			return i
		}
	}
	return -1
}
