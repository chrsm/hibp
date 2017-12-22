package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type resp struct {
	breaches Breaches
	err      error
}

type req struct {
	email    string
	passback chan resp
}

type Client struct {
	xport *http.Client

	requests chan req
	quit     chan struct{}
}

func NewClient(xport *http.Client) *Client {
	if xport == nil {
		xport = http.DefaultClient
	}

	c := &Client{
		xport:    xport,
		quit:     make(chan struct{}),
		requests: make(chan req),
	}

	go c.proc()

	return c
}

func (c *Client) Close() {
	c.quit <- struct{}{}
}

// proc rate limits requests to hibp's 1/s by processing requests;
// they come in on a channel and are responded to.
func (c *Client) proc() {
	limit := time.Tick(time.Second)

lewp:
	for {
		select {
		case req := <-c.requests:
			<-limit

			hresp, err := c.xport.Get(fmt.Sprintf("https://haveibeenpwned.com/api/v2/breachedaccount/%s", req.email))
			if err != nil {
				// do something
			}
			defer hresp.Body.Close()

			if hresp.StatusCode == 200 {
				var br Breaches
				json.NewDecoder(hresp.Body).Decode(&br)

				req.passback <- resp{
					breaches: br,
					err:      nil,
				}
			} else {
				req.passback <- resp{
					breaches: nil,
					err:      fmt.Errorf("Request error: %d", hresp.StatusCode),
				}
			}

			close(req.passback)

		case <-c.quit:
			close(c.quit)
			close(c.requests)

			break lewp
		}
	}
}

func (c *Client) BreachedAccount(email string) (Breaches, error) {
	cresp := make(chan resp)
	req := req{
		email:    email,
		passback: cresp,
	}

	c.requests <- req
	resp := <-cresp

	return resp.breaches, resp.err
}
