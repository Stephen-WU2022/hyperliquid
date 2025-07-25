package hyperliquid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const ExchangeEndpoint = "https://api.hyperliquid.xyz"

type OrderStatusPac string

const (
	StatusResting OrderStatusPac = "resting"
	StatusFilled  OrderStatusPac = "filled"
	StatusError   OrderStatusPac = "error"
	StatusUnknown OrderStatusPac = "unknown"
)

type Tif string

const (
	TifGtc Tif = "Gtc"
	TifIoc Tif = "Ioc"
	TifAlo Tif = "Alo"
)

const GroupingNA = "na"

type OrderType struct {
	Limit   *LimitOrderType   `json:"limit,omitempty"`
	Trigger *TriggerOrderType `json:"trigger,omitempty"`
}

type LimitOrderType struct {
	Tif string `json:"tif"` // TifAlo, TifIoc, TifGtc
}

type TriggerOrderType struct {
	TriggerPx string `json:"triggerPx"`
	IsMarket  bool   `json:"isMarket"`
	Tpsl      string `json:"tpsl"` // "tp" or "sl"
}

type internalOrderRequest struct {
	Asset         int       `json:"a" msgpack:"a"`
	IsBuy         bool      `json:"b" msgpack:"b"`
	Price         string    `json:"p" msgpack:"p"`
	Size          string    `json:"s" msgpack:"s"`
	ReduceOnly    bool      `json:"r" msgpack:"r"`
	OrderType     OrderType `json:"t" msgpack:"t"`
	ClientOrderID *string   `json:"c,omitempty" msgpack:"c,omitempty"`
}

type ApiResponse struct {
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response"`
}

type ResponseData struct {
	Type string        `json:"type"`
	Data StatusWrapper `json:"data"`
}

type StatusWrapper struct {
	Statuses []json.RawMessage `json:"statuses"`
}

type StatusDetail struct {
	Oid uint64 `json:"oid"`
}

type OrderAction struct {
	Type     string                 `msgpack:"type" json:"type"`
	Orders   []internalOrderRequest `msgpack:"orders" json:"orders"`
	Grouping string                 `msgpack:"grouping" json:"grouping"`
}
type Client struct {
	address     string
	privateKey  string
	client      *http.Client
	logger      *log.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	rateLimiter <-chan time.Time
	assetMap    map[string]int
}

func floatToString(f float64) string {
	s := strconv.FormatFloat(f, 'f', 15, 64)
	s = strings.TrimRight(s, "0")
	if s[len(s)-1] == '.' {
		return s + "0"
	}
	return s
}

func NewClient(address, privateKey string, logger *log.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		address:     address,
		privateKey:  privateKey,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
		rateLimiter: time.Tick(20 * time.Millisecond),
		assetMap:    map[string]int{"BTC": 13, "ETH": 14},
	}
}

func (c *Client) PlaceOrder(orderType, symbol, side string, size, price float64, reduceOnly bool) (OpenOrderInfo, error) {
	assetID, ok := c.assetMap[strings.ToUpper(symbol)]
	if !ok {
		return OpenOrderInfo{}, fmt.Errorf("asset symbol not found: %s", symbol)
	}

	isBuy := strings.ToLower(side) == "buy"

	priceWire, err := floatToWire(price)
	if err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to process price for wire format: %w", err)
	}
	sizeWire, err := floatToWire(size)
	if err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to process size for wire format: %w", err)
	}

	var orderTypeData OrderType
	switch strings.ToLower(orderType) {
	case "limit":
		orderTypeData.Limit = &LimitOrderType{Tif: string(TifGtc)}
	case "market":
		tpsl := "sl"
		if isBuy {
			tpsl = "tp"
		}
		orderTypeData.Trigger = &TriggerOrderType{
			TriggerPx: priceWire,
			IsMarket:  true,
			Tpsl:      tpsl,
		}
	default:
		return OpenOrderInfo{}, fmt.Errorf("unsupported order type: %s", orderType)
	}

	orderRequest := internalOrderRequest{
		Asset:         assetID,
		IsBuy:         isBuy,
		Price:         priceWire, // The trigger price is also used here for the order payload
		Size:          sizeWire,
		ReduceOnly:    reduceOnly,
		OrderType:     orderTypeData,
		ClientOrderID: nil,
	}
	action := OrderAction{
		Type:     "order",
		Orders:   []internalOrderRequest{orderRequest},
		Grouping: GroupingNA,
	}

	respBytes, err := c.sendRequest(http.MethodPost, "exchange", action, true)
	if err != nil {
		return OpenOrderInfo{}, err
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(respBytes, &apiResponse); err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to unmarshal initial api response: %w", err)
	}

	if apiResponse.Status != "ok" {
		var errorString string
		if err := json.Unmarshal(apiResponse.Response, &errorString); err == nil {
			return OpenOrderInfo{}, fmt.Errorf("order placement failed with status '%s': %s", apiResponse.Status, errorString)
		}
		return OpenOrderInfo{}, fmt.Errorf("order placement failed with status '%s' and unparseable error response: %s", apiResponse.Status, string(apiResponse.Response))
	}

	var responseData ResponseData
	if err := json.Unmarshal(apiResponse.Response, &responseData); err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to unmarshal successful response data: %w", err)
	}

	if len(responseData.Data.Statuses) == 0 {
		return OpenOrderInfo{}, errors.New("no order status returned")
	}

	var statusData map[string]interface{}
	if err := json.Unmarshal(responseData.Data.Statuses[0], &statusData); err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to unmarshal order status: %w", err)
	}

	if status, ok := statusData["resting"]; ok {
		statusInfo := status.(map[string]interface{})
		oid := uint64(statusInfo["oid"].(float64))
		return OpenOrderInfo{
			Ts:        time.Now(),
			Symbol:    symbol,
			OrderType: orderType,
			OrderId:   strconv.FormatUint(oid, 10),
			Side:      side,
		}, nil
	} else if errorMsg, ok := statusData["error"]; ok {
		return OpenOrderInfo{}, fmt.Errorf("order placement error from API: %s", errorMsg.(string))
	}

	return OpenOrderInfo{}, errors.New("unknown order status returned in response")
}

func (c *Client) newRequest(method, path string, payload interface{}, sign bool) (*http.Request, error) {
	var body io.Reader
	var reqBodyBytes []byte
	var err error

	if payload != nil {
		if sign {
			nonce := time.Now().UnixMilli()

			hash := actionHash(payload, "", nonce, nil)

			// 2. Construct the phantom agent for signing
			phantomAgent := constructPhantomAgent(hash, true)

			// 3. Create the EIP-712 typed data payload
			typedData := l1Payload(phantomAgent)

			// 4. Sign the typed data
			privateKey, err := PrivateKeyFromString(c.privateKey)
			signature, err := signInner(privateKey, typedData)
			if err != nil {
				return nil, fmt.Errorf("failed to sign payload: %w", err)
			}

			signedPayload := map[string]interface{}{
				"action":    payload,
				"nonce":     nonce,
				"signature": signature,
			}
			reqBodyBytes, err = json.Marshal(signedPayload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal signed payload: %w", err)
			}
		} else {
			reqBodyBytes, err = json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal non-signed payload: %w", err)
			}
		}
	}

	if reqBodyBytes != nil {
		body = bytes.NewBuffer(reqBodyBytes)
	}

	url := fmt.Sprintf("%s/%s", ExchangeEndpoint, path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	return req, nil
}

func (c *Client) sendRequest(method, path string, data interface{}, sign bool) ([]byte, error) {
	<-c.rateLimiter
	req, err := c.newRequest(method, path, data, sign)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var errorCheck map[string]interface{}
	if json.Unmarshal(response, &errorCheck) == nil {
		if errorMsg, ok := errorCheck["error"]; ok {
			return nil, errors.New(errorMsg.(string))
		}
	}

	return response, nil
}

func floatToWire(x float64) (string, error) {
	rounded := fmt.Sprintf("%.8f", x)

	parsed, err := strconv.ParseFloat(rounded, 64)
	if err != nil {
		return "", err
	}
	if math.Abs(parsed-x) >= 1e-9 {
		return "", fmt.Errorf("float_to_wire causes rounding error: original %f, rounded %f", x, parsed)
	}

	if rounded == "-0.00000000" {
		rounded = "0.00000000"
	}

	result := strings.TrimRight(rounded, "0")
	result = strings.TrimRight(result, ".")

	return result, nil
}
