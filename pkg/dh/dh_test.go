package dh

import (
	"testing"
)

func TestDH(t *testing.T) {
	if !sessionCmpTest()  {
		t.Error("session keys is not equal")
	}

	if !normalFlowTest()  {
		t.Error("normal flow failed")
	}

	if !mitmFlowTest()  {
		t.Error("mitm attack failed")
	}

	if !g1FlowTest() {
		t.Error("g==1 attack failed")
	}

	if !gpFlowTest() {
		t.Error("g==p attack failed")
	}

	if !gp1FlowTest() {
		t.Error("g==p-1 attack failed")
	}
}