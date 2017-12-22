package hibp

import (
	"testing"
)

func TestClient(t *testing.T) {
	c := NewClient(nil)

	breaches, err := c.BreachedAccount("test@example.com")

	if err != nil {
		t.Fatal("Err should be nil")
	}

	if len(breaches) == 0 {
		t.Fatal("breaches should be >0")
	}

	c.Close()
}
