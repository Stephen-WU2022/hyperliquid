package hyperliquid

import (
	"fmt"
	"testing"
)

func Test_Order(t *testing.T) {
	client := NewClient("0xb827b5f16be8b75b5eb29202bce54eaeada6cebd", "", nil)

	openOrderInfo, err := client.PlaceOrder("limit", "ETH", "buy", 0.0030, 3000.0)
	if err != nil {
		fmt.Println("Error placing order:", err)
	}
	fmt.Println("Open Order Info:", openOrderInfo)

}
