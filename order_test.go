package hyperliquid

import (
	"fmt"
	"testing"
)

func Test_Order(t *testing.T) {
	client := NewClient("0xb827b5f16be8b75b5eb29202bce54eaeada6cebd", "0x9c0d9ff46743eece3fd414176c8316635c0bbdf93258a760aca8e38c1df9decc", nil)

	openOrderInfo, err := client.PlaceOrder("limit", "ETH", "buy", 0.003, 3000)
	if err != nil {
		fmt.Println("Error placing order:", err)
	}
	fmt.Println("Open Order Info:", openOrderInfo)

}
