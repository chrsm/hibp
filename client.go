package hibp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

func (r *req) pass(b Breaches, err error) {
	r.passback <- resp{
		breaches: b,
		err:      err,
	}
}

type Client struct {
	xport *http.Client

	requests chan req

	closed bool
	quit   chan struct{}
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
	if c.closed {
		return
	}

	c.closed = true
	c.quit <- struct{}{}
}

// Rate limit all queries to HIBP's API.
func (c *Client) proc() {
	limit := time.Tick(time.Second * 2)

lewp:
	for {
		select {
		case req := <-c.requests:
			<-limit

			get, err := http.NewRequest("GET", fmt.Sprintf("https://haveibeenpwned.com/api/v2/breachedaccount/%s", url.PathEscape(req.email)), nil)
			if err != nil {
				req.pass(nil, err)
				continue
			}

			get.Header.Set("User-Agent", "Pwn-Checker-Go")

			hresp, err := c.xport.Do(get)
			if err != nil {
				req.pass(nil, err)
				continue
			}
			defer hresp.Body.Close()

			if hresp.StatusCode == 200 {
				br := make(Breaches, 0)
				err := json.NewDecoder(hresp.Body).Decode(&br)

				req.pass(br, err)
			} else {
				req.pass(nil, fmt.Errorf("Request error: %d", hresp.StatusCode))
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
	if c.closed {
		return nil, fmt.Errorf("Attempting to use Client after it has been closed!")
	}

	cresp := make(chan resp)
	req := req{
		email:    email,
		passback: cresp,
	}

	c.requests <- req
	resp := <-cresp

	return resp.breaches, resp.err
}
