package hyperliquid

import (
	"fmt"
	"testing"
)

func Test_Order(t *testing.T) {
	client := NewClient("0x070cea445cb8fb15161f4db337112f4aea63e931", "d19daaca4cefca95c37c03f859a969d010927f1594359ddbe960a942d2bddd41", nil)

	openOrderInfo, err := client.PlaceOrder("limit", "ETH", "buy", 0.0030, 3000, false)
	if err != nil {
		fmt.Println("Error placing order:", err)
	}
	fmt.Println("Open Order Info:", openOrderInfo)

}
