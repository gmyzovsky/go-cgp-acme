package main

import (
	"reflect"
	"testing"
)

func TestSubtractRemovesSharedDomains(t *testing.T) {
	// The --onlylocal case: LISTDOMAINS minus the Shared list leaves the
	// main domain and any regular non-Shared domains, order preserved.
	all := []string{"main.example.com", "shared1.example.com", "local.example.com", "shared2.example.com"}
	shared := []string{"shared1.example.com", "shared2.example.com"}
	got := subtract(all, shared)
	want := []string{"main.example.com", "local.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subtract = %v, want %v", got, want)
	}
}

func TestSubtractEmptyShared(t *testing.T) {
	// On a non-cluster server LISTCONTROLLEDDOMAINS is empty, so
	// --onlylocal degrades to the full domain list.
	all := []string{"a.example.com", "b.example.com"}
	got := subtract(all, nil)
	if !reflect.DeepEqual(got, all) {
		t.Fatalf("subtract with no shared = %v, want %v", got, all)
	}
}
