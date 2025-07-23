package hyperliquid

import "time"

type OrderStatus int

const (
	Init OrderStatus = iota
	Pending
	Rejected
	Filled
	Cancelling
	Canceled
	New
	Placed
	PartialFill
	Open
)

type ICex interface {
	SubscribeMarketData(subScribeMarketData func(MarketInfo))
	SubscribeOrderUpdate(subScribeOrderUpdate func(OrderUpdateInfo))
	SubscribeTrade(subScribeTrade func(TradeInfo))
	PlaceOrder(orderType, symbol, side string, size, price float64) OpenOrderInfo
	CancelOrder(symbol string, oid string) OpenOrderInfo
	GetBalanceInfo() []BalanceInfo
	GetPositionInfo() []PositionInfo
	GetAllOpenOrders(symbol string) []OpenOrderInfo
}

type MarketInfo struct {
	Symbol   string
	Asks     [][]float64
	Bids     [][]float64
	MidPrice float64
	Ts       time.Time
	Exch_Ts  time.Time
}

type OrderUpdateInfo struct {
	Ts        time.Time
	Status    OrderStatus
	Symbol    string
	Side      string
	Size      float64
	Price     float64
	OrderId   string
	OrderType string
}

type OpenOrderInfo struct {
	Ts         time.Time
	Symbol     string
	OrderType  string
	OrderId    string
	Size       float64
	OrderPrice float64
	Side       string
	Status     OrderStatus
}

type BalanceInfo struct {
	Token   string
	Holding float64
	Frozen  float64
}

type PositionInfo struct {
	Token            string
	Position         float64
	EntryPrice       float64
	RealisedPnl      float64
	UnPnl            float64
	PositionNotional float64
}

type TradeInfo struct {
	Symbol string
	Price  float64
	Size   float64
	Ts     time.Time
}
