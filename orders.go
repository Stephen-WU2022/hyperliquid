package hyperliquid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/math"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
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

type PlaceOrderAction struct {
	Type     string         `json:"type"`
	Orders   []OrderPayload `json:"orders"`
	Grouping string         `json:"grouping"`
}

type LimitOrderType struct {
	Tif string `json:"tif"`
}

type MarketOrderType struct {
	Tif string `json:"tif"`
}

type OrderTypeData struct {
	Limit  *LimitOrderType  `json:"limit,omitempty"`
	Market *MarketOrderType `json:"market,omitempty"`
}

type OrderPayload struct {
	Asset      int           `json:"a"`
	IsBuy      bool          `json:"b"`
	LimitPx    string        `json:"p"`
	Sz         string        `json:"s"`
	ReduceOnly bool          `json:"r"`
	OrderType  OrderTypeData `json:"t"`
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
	// Format with 'f' and a high precision to prevent scientific notation.
	s := strconv.FormatFloat(f, 'f', 10, 64)
	// Remove trailing zeros.
	s = strings.TrimRight(s, "0")
	// If the last character is a dot, remove it.
	s = strings.TrimSuffix(s, ".")
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

func (c *Client) PlaceOrder(orderType, symbol, side string, size, price float64) (OpenOrderInfo, error) {
	assetID, ok := c.assetMap[strings.ToUpper(symbol)]
	if !ok {
		return OpenOrderInfo{}, fmt.Errorf("asset symbol not found: %s", symbol)
	}

	isBuy := strings.ToLower(side) == "buy"

	var orderTypeData OrderTypeData
	switch orderType {
	case "limit":
		orderTypeData.Limit = &LimitOrderType{Tif: "Gtc"}
	case "market":
		orderTypeData.Market = &MarketOrderType{Tif: "Ioc"}
	default:
		return OpenOrderInfo{}, fmt.Errorf("unsupported order type: %s", orderType)
	}

	orderPayload := OrderPayload{
		Asset:      assetID,
		IsBuy:      isBuy,
		ReduceOnly: false,
		LimitPx:    floatToString(price),
		Sz:         floatToString(size),
		OrderType:  orderTypeData,
	}

	action := PlaceOrderAction{
		Type:     "order",
		Orders:   []OrderPayload{orderPayload},
		Grouping: "na",
	}

	respBytes, err := c.sendRequest(http.MethodPost, "exchange", action, true)
	if err != nil {
		return OpenOrderInfo{}, err
	}

	// First, unmarshal into the flexible ApiResponse struct.
	var apiResponse ApiResponse
	if err := json.Unmarshal(respBytes, &apiResponse); err != nil {
		return OpenOrderInfo{}, fmt.Errorf("failed to unmarshal initial api response: %w", err)
	}

	// If the status is not "ok", the 'Response' field contains an error string.
	if apiResponse.Status != "ok" {
		var errorString string
		// Attempt to unmarshal the 'Response' field as a simple string.
		if err := json.Unmarshal(apiResponse.Response, &errorString); err == nil {
			return OpenOrderInfo{}, fmt.Errorf("order placement failed with status '%s': %s", apiResponse.Status, errorString)
		}
		// If that fails, just return the raw response.
		return OpenOrderInfo{}, fmt.Errorf("order placement failed with status '%s' and unparseable error response: %s", apiResponse.Status, string(apiResponse.Response))
	}

	// If status is "ok", then we can unmarshal the 'Response' field into the expected ResponseData struct.
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
			Ts:         time.Now(),
			Symbol:     symbol,
			OrderType:  orderType,
			OrderId:    strconv.FormatUint(oid, 10),
			Size:       size,
			OrderPrice: price,
			Side:       side,
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

			// --- CHANGE #2: Use json.Marshal for robust, newline-free marshalling ---
			// This matches the go-sdk's implementation.
			actionBytes, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal action payload: %w", err)
			}

			connectionID, err := c.createConnectionId(actionBytes, nonce)
			if err != nil {
				return nil, fmt.Errorf("failed to create connectionId: %w", err)
			}

			signature, err := c.signEIP712(connectionID)
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

func (c *Client) createConnectionId(actionBytes []byte, nonce int64) (common.Hash, error) {
	// The order of arguments and types MUST match the server's expectation.
	// The expected order is: address, string, uint64
	addressArgument, err := abi.NewType("address", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	stringArgument, err := abi.NewType("string", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	uint64Argument, err := abi.NewType("uint64", "", nil)
	if err != nil {
		return common.Hash{}, err
	}

	// Define the arguments in the correct order
	arguments := abi.Arguments{
		{Type: addressArgument},
		{Type: stringArgument},
		{Type: uint64Argument},
	}

	// Convert the client's hex address string to a common.Address type
	userAddress := common.HexToAddress(c.address)

	// Pack the arguments in the correct order: your address, the action, and the nonce.
	packed, err := arguments.Pack(userAddress, string(actionBytes), uint64(nonce))
	if err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(packed), nil
}

type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}

func (c *Client) signEIP712(connectionID common.Hash) (Signature, error) {
	privateKeyECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(c.privateKey, "0x"))
	if err != nil {
		return Signature{}, fmt.Errorf("failed to parse private key: %w", err)
	}

	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Agent": []apitypes.Type{
				{Name: "source", Type: "string"},
				{Name: "connectionId", Type: "bytes32"},
			},
		},
		PrimaryType: "Agent",
		Domain: apitypes.TypedDataDomain{
			Name:              "HyperliquidSigner",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(1337),
			VerifyingContract: "0x0000000000000000000000000000000000000000",
		},
		Message: apitypes.TypedDataMessage{
			"source":       "a",
			"connectionId": connectionID,
		},
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return Signature{}, fmt.Errorf("failed to hash domain: %w", err)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return Signature{}, fmt.Errorf("failed to hash message: %w", err)
	}

	// CORRECTED HASHING:
	// The crypto.Keccak256Hash function will concatenate the arguments correctly.
	challengeHash := crypto.Keccak256Hash(
		[]byte("\x19\x01"),
		domainSeparator,
		typedDataHash,
	)

	signatureBytes, err := crypto.Sign(challengeHash.Bytes(), privateKeyECDSA)
	if err != nil {
		return Signature{}, fmt.Errorf("failed to sign: %w", err)
	}

	// The API expects the old standard of V being 27 or 28.
	signatureBytes[64] += 27

	// CORRECTED RETURN TYPE:
	// Populate and return the Signature struct.
	return Signature{
		R: hexutil.Encode(signatureBytes[0:32]),
		S: hexutil.Encode(signatureBytes[32:64]),
		V: signatureBytes[64],
	}, nil
}
