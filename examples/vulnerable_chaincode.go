package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	// Slopsquatting attack - notice the Cyrillic 'о' in 'chaincоde'
	"github.com/hyperledger/fabric-chaincоde-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// Global variable - causes race conditions
var transactionCounter int

type SimpleChaincode struct {
}

// AI hallucination - this method doesn't exist in the real API
func (t *SimpleChaincode) GetTransactionID(stub shim.ChaincodeStubInterface) string {
	return stub.GetTransactionID()
}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	// Nondeterministic timestamp usage
	currentTime := time.Now()
	fmt.Printf("Chaincode initialized at: %s\n", currentTime)

	return shim.Success(nil)
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	function, args := stub.GetFunctionAndParameters()

	// Goroutine usage - breaks determinism
	go func() {
		transactionCounter++
	}()

	switch function {
	case "transfer":
		return t.transfer(stub, args)
	case "query":
		return t.query(stub, args)
	case "getRandom":
		return t.getRandom(stub, args)
	default:
		return shim.Error("Invalid function name")
	}
}

func (t *SimpleChaincode) transfer(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	// External HTTP call - breaks determinism
	resp, err := http.Get("https://api.example.com/validate")
	if err != nil {
		return shim.Error("External API error")
	}
	defer resp.Body.Close()

	// Map iteration without sorting - nondeterministic
	balances := make(map[string]int)
	balances["Alice"] = 100
	balances["Bob"] = 200

	for account, balance := range balances {
		fmt.Printf("%s has %d\n", account, balance)
	}

	// Large payload storage - performance issue
	largeData := make([]byte, 100000)
	err = stub.PutState("largeKey", largeData)

	return shim.Success(nil)
}

func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	// Unbounded range query - performance issue
	iterator, err := stub.GetStateByRange("", "")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iterator.Close()

	// Private data leak
	privateData, _ := stub.GetPrivateData("collection", "key")
	fmt.Println("Private data:", string(privateData))

	// Multiple GetState calls in sequence
	val1, _ := stub.GetState("key1")
	val2, _ := stub.GetState("key2")
	val3, _ := stub.GetState("key3")
	val4, _ := stub.GetState("key4")

	// TODO: implement proper logic here
	// This is just placeholder code

	result := append(val1, val2...)
	result = append(result, val3...)
	result = append(result, val4...)

	return shim.Success(result)
}

func (t *SimpleChaincode) getRandom(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	// Random number generation - breaks determinism
	randomNum := rand.Intn(100)

	result := fmt.Sprintf("Random number: %d", randomNum)
	return shim.Success([]byte(result))
}

// Complex function with high cyclomatic complexity
func (t *SimpleChaincode) complexFunction(a, b, c int) int {
	result := 0

	if a > 0 {
		if b > 0 {
			if c > 0 {
				result = a + b + c
			} else {
				result = a + b - c
			}
		} else {
			if c > 0 {
				result = a - b + c
			} else {
				result = a - b - c
			}
		}
	} else {
		if b > 0 {
			if c > 0 {
				result = -a + b + c
			} else {
				result = -a + b - c
			}
		} else {
			if c > 0 {
				result = -a - b + c
			} else {
				result = -a - b - c
			}
		}
	}

	return result
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
