package hyperliquid

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type wsRequest struct {
	Method       string       `json:"method"`
	Subscription subscription `json:"subscription"`
}

type subscription struct {
	Type string `json:"type"`
	Coin string `json:"coin"`
}

type wsResponse struct {
	Channel string          `json:"channel"`
	Data    json.RawMessage `json:"data"`
}

type l2BookData struct {
	Coin   string          `json:"coin"`
	Time   int64           `json:"time"`
	Levels [][]levelUpdate `json:"levels"`
}

type levelUpdate struct {
	Px string `json:"px"`
	Sz string `json:"sz"`
	N  int    `json:"n"`
}

type OrderBookBranch struct {
	Symbol             string
	cancel             context.CancelFunc
	logger             *log.Logger
	marketDataCallback func(MarketInfo)
	snapshotReceived   bool
	updateBuffer       []l2BookData
	bufferLock         sync.Mutex

	bookMu sync.RWMutex
	bids   map[string]string
	asks   map[string]string
}

func (o *OrderBookBranch) handleSnapshot(bids, asks []levelUpdate) {
	o.bookMu.Lock()
	defer o.bookMu.Unlock()

	o.bids = make(map[string]string)
	o.asks = make(map[string]string)

	for _, level := range bids {
		o.bids[level.Px] = level.Sz
	}
	for _, level := range asks {
		o.asks[level.Px] = level.Sz
	}
}

func (o *OrderBookBranch) handleUpdate(levels [][]levelUpdate) {
	o.bookMu.Lock()
	defer o.bookMu.Unlock()

	for _, level := range levels[0] {
		size, err := strconv.ParseFloat(level.Sz, 64)
		if err != nil {
			continue
		}
		if size == 0.0 {
			delete(o.bids, level.Px)
		} else {
			o.bids[level.Px] = level.Sz
		}
	}

	for _, level := range levels[1] {
		size, err := strconv.ParseFloat(level.Sz, 64)
		if err != nil {
			continue
		}
		if size == 0.0 {
			delete(o.asks, level.Px)
		} else {
			o.asks[level.Px] = level.Sz
		}
	}
}

func (o *OrderBookBranch) getSides() (bids, asks [][]float64) {
	o.bookMu.RLock()
	defer o.bookMu.RUnlock()

	bids = make([][]float64, 0, len(o.bids))
	for px, sz := range o.bids {
		price, _ := strconv.ParseFloat(px, 64)
		size, _ := strconv.ParseFloat(sz, 64)
		bids = append(bids, []float64{price, size})
	}

	asks = make([][]float64, 0, len(o.asks))
	for px, sz := range o.asks {
		price, _ := strconv.ParseFloat(px, 64)
		size, _ := strconv.ParseFloat(sz, 64)
		asks = append(asks, []float64{price, size})
	}

	sort.Slice(bids, func(i, j int) bool {
		return bids[i][0] > bids[j][0]
	})

	sort.Slice(asks, func(i, j int) bool {
		return asks[i][0] < asks[j][0]
	})

	return bids, asks
}

func NewLocalOrderBook(ctx context.Context, symbol string, logger *log.Logger, callback func(MarketInfo)) *OrderBookBranch {
	childCtx, cancel := context.WithCancel(ctx)

	o := &OrderBookBranch{
		Symbol:             symbol,
		cancel:             cancel,
		logger:             logger,
		marketDataCallback: callback,
		snapshotReceived:   false,
		updateBuffer:       make([]l2BookData, 0),
		bids:               make(map[string]string),
		asks:               make(map[string]string),
	}

	go func() {
		for {
			select {
			case <-childCtx.Done():
				return
			default:
				if err := o.hyperliquidSocket(childCtx, symbol); err != nil {
					o.logger.Warnf("hyperliquidSocket for %s reconnecting: %v", symbol, err)
					o.snapshotReceived = false
					o.handleSnapshot([]levelUpdate{}, []levelUpdate{})
					time.Sleep(5 * time.Second)
				} else {
					o.logger.Infof("hyperliquidSocket for %s stopped.", symbol)
					return
				}
			}
		}
	}()

	return o
}

func (o *OrderBookBranch) hyperliquidSocket(ctx context.Context, symbol string) error {
	url := "wss://api.hyperliquid.xyz/ws"
	dialCtx, dialCancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
	defer dialCancel()

	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, url, nil)
	if err != nil {
		o.logger.Errorf("Failed to dial websocket for %s: %v", symbol, err)
		return err
	}
	defer conn.Close()
	o.logger.Infof("Successfully connected to Hyperliquid websocket for %s", symbol)

	subMsg := wsRequest{
		Method: "subscribe",
		Subscription: subscription{
			Type: "l2Book",
			Coin: strings.ToUpper(symbol),
		},
	}
	if err := conn.WriteJSON(subMsg); err != nil {
		o.logger.Errorf("Failed to send subscription for %s: %v", symbol, err)
		return err
	}
	o.logger.Infof("Subscription message sent for %s", symbol)

	msgChan := make(chan []byte)
	errChan := make(chan error, 1)

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errChan:
			o.logger.Errorf("Error reading from websocket for %s: %v", symbol, err)
			return err
		case msg := <-msgChan:
			var pingCheck map[string]interface{}
			if err := json.Unmarshal(msg, &pingCheck); err == nil {
				if method, ok := pingCheck["method"]; ok && method == "ping" {
					o.logger.Info("Received ping, sending pong.")
					pongMsg := map[string]string{"method": "pong"}
					if err := conn.WriteJSON(pongMsg); err != nil {
						o.logger.Errorf("Failed to send pong for %s: %v", symbol, err)
						return err
					}
					continue
				}
			}

			if err := o.handleMessage(msg); err != nil {
				o.logger.Errorf("Error handling message for %s: %v", symbol, err)
			}
		}
	}
}

func (o *OrderBookBranch) handleMessage(msg []byte) error {
	var resp wsResponse
	if err := json.Unmarshal(msg, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal base response: %w", err)
	}

	if resp.Channel != "l2Book" {
		return nil
	}

	var data l2BookData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return fmt.Errorf("failed to unmarshal l2Book data: %w", err)
	}

	o.bufferLock.Lock()

	o.handleSnapshot(data.Levels[0], data.Levels[1])
	o.snapshotReceived = true

	for _, bufferedUpdate := range o.updateBuffer {
		if bufferedUpdate.Time > data.Time {
			o.handleUpdate(bufferedUpdate.Levels)
		}
		o.updateBuffer = make([]l2BookData, 0)
	}

	o.bufferLock.Unlock()
	if o.snapshotReceived {
		fmt.Println(o.getSides())
		o.triggerCallback(data.Time)
	}

	return nil
}

func (o *OrderBookBranch) triggerCallback(exchTs int64) {
	if o.marketDataCallback == nil {
		return
	}

	bids, asks := o.getSides()

	if len(bids) == 0 || len(asks) == 0 {
		return
	}

	bestBid := bids[0][0]
	bestAsk := asks[0][0]
	midPrice := (bestBid + bestAsk) / 2

	marketInfo := MarketInfo{
		Symbol:   o.Symbol,
		Asks:     asks,
		Bids:     bids,
		MidPrice: midPrice,
		Ts:       time.Now().UTC(),
		Exch_Ts:  time.UnixMilli(exchTs),
	}

	o.marketDataCallback(marketInfo)
}

func (o *OrderBookBranch) Close() {
	o.logger.Infof("Closing order book handler for %s", o.Symbol)
	o.cancel()
}

func isSnapshot(data json.RawMessage) bool {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return false
	}
	_, isSnapshot := v["isSnapshot"]
	return isSnapshot
}
