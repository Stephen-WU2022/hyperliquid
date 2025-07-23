package hyperliquid

import (
	"fmt"
	"testing"
)

func Test_Order(t *testing.T) {
	client := NewClient("0x7Ea2d7B5351317FE024647ef0DAd9A7D20C3eC59", "", nil)

	openOrderInfo, err := client.PlaceOrder("limit", "ETH", "buy", 10, 3000)
	if err != nil {
		fmt.Println("Error placing order:", err)
	}
	fmt.Println("Open Order Info:", openOrderInfo)

}
