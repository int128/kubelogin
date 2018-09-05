package cli

import (
	"testing"
)

func TestParse(t *testing.T) {
	c, err := Parse([]string{"kubelogin"}, "version")
	if err != nil {
		t.Errorf("Parse returned error: %s", err)
	}
	if c == nil {
		t.Errorf("Parse should return CLI but nil")
	}
}

func TestParse_TooManyArgs(t *testing.T) {
	c, err := Parse([]string{"kubelogin", "some"}, "version")
	if err == nil {
		t.Errorf("Parse should return error but nil")
	}
	if c != nil {
		t.Errorf("Parse should return nil but %+v", c)
	}
}

func TestParse_Help(t *testing.T) {
	c, err := Parse([]string{"kubelogin", "--help"}, "version")
	if err == nil {
		t.Errorf("Parse should return error but nil")
	}
	if c != nil {
		t.Errorf("Parse should return nil but %+v", c)
	}
}
