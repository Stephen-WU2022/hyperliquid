package hyperliquid

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func manuallyStop(cancel *context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("\nCtrl+C pressed, shutting down.")
	(*cancel)()
	time.Sleep(1 * time.Second)
}

func Test_LocalOrderBook(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	ctx, cancel := context.WithCancel(context.Background())

	marketDataCallback := func(info MarketInfo) {
		if len(info.Bids) > 0 && len(info.Asks) > 0 {
			fmt.Println(info.Symbol, "Best Bid:", info.Bids[0], "Best Ask:", info.Asks[0], "Mid Price:", info.MidPrice)
			t.Logf("Received update for %s: Best Bid: %v, Best Ask: %v, Mid: %f",
				info.Symbol, info.Bids[0], info.Asks[0], info.MidPrice)
		} else {
			fmt.Println(info.Symbol, "Received update with empty book side.")
			t.Logf("Received update for %s with empty book side.", info.Symbol)
		}
	}

	t.Log("Starting local order book for BTC. Press Ctrl+C to stop.")
	_ = NewLocalOrderBook(ctx, "BTC", logger, marketDataCallback)

	manuallyStop(&cancel)
	t.Log("Test finished.")
}
