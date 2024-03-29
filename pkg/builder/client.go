package builder

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/andriidski/relay-monitor-fuzzer/pkg/types"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

const clientTimeoutSec = 2

type Client struct {
	endpoint  string
	hostname  string
	PublicKey types.PublicKey
	client    http.Client
}

func (c *Client) Endpoint() string {
	return c.endpoint
}

func (c *Client) Hostname() string {
	return c.hostname
}

func (c *Client) String() string {
	return c.PublicKey.String()
}

func NewClient(endpoint string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	hostname := u.Hostname()

	publicKeyStr := u.User.Username()
	var publicKey types.PublicKey
	err = publicKey.UnmarshalText([]byte(publicKeyStr))
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: clientTimeoutSec * time.Second,
	}
	return &Client{
		endpoint:  endpoint,
		hostname:  hostname,
		PublicKey: publicKey,
		client:    client,
	}, nil
}

// GetStatus implements the `status` endpoint in the Builder API
func (c *Client) GetStatus() error {
	statusUrl := c.endpoint + "/eth/v1/builder/status"
	req, err := http.NewRequest(http.MethodGet, statusUrl, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay status was not healthy with HTTP status code %d", resp.StatusCode)
	}
	return nil
}

// GetBid implements the `getHeader` endpoint in the Builder API.
// A return value of `(nil, nil)` indicates the relay was reachable but had no bid for the given parameters
func (c *Client) GetBid(slot types.Slot, parentHash types.Hash, publicKey types.PublicKey) (*types.Bid, error) {
	bidUrl := c.endpoint + fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHash, publicKey)

	req, err := http.NewRequest(http.MethodGet, bidUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get bid with HTTP status code %d", resp.StatusCode)
	}

	var bid boostTypes.GetHeaderResponse
	err = json.NewDecoder(resp.Body).Decode(&bid)
	return bid.Data, err
}
