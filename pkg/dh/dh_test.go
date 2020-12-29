package dh

import (
	"testing"
)

func TestEasyDhAttack(t *testing.T) {
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

	if !smallSubGroupAttack() {
		t.Error("small subgroup attack failed")
	}
}

func TestSmallSubGroupAttack(t *testing.T) {
	if !smallSubGroupAttack() {
		t.Error("small subgroup attack failed")
	}
}