package hibp

import (
	"testing"
)

// TestAll runs the actual tests sequentially, as HIBP will temporarily block you for bypassing the rate limiter
func TestAll(t *testing.T) {
	c := NewClient(nil)

	tClientBasic(c, t)
	tClientBreaches(c, t)
	tClientClosed(c, t)
}

func tClientBasic(c *Client, t *testing.T) {
	breaches, err := c.BreachedAccount("test@example.com")

	if err != nil {
		t.Fatal("Err should be nil")
	}

	if len(breaches) == 0 {
		t.Fatal("breaches should be >0")
	}
}

func tClientBreaches(c *Client, t *testing.T) {
	breaches, err := c.BreachedAccount("test@example.com")
	if err != nil {
		t.Fatal("Failed to get breaches for test@example.com")
	}

	got := false
	for i := range breaches {
		if breaches[i].Title != "Adobe" {
			continue
		}

		got = true
	}

	if !got {
		t.Error("Unable to find Adobe.com breach in response")
	}
}

func tClientClosed(c *Client, t *testing.T) {
	c.Close()

	_, err := c.BreachedAccount("test@example.com")
	if err == nil {
		t.Fatal("Was able to query API after closing client")
	}
}
