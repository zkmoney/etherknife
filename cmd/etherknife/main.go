package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "etherknife"
	app.Usage = "Ethereum Swiss Army Knife"

	var tc TxnContext
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "to, t",
			Value:       "",
			Usage:       "to `address` in transaction",
			Destination: &tc.To,
		},
		cli.StringFlag{
			Name:        "amount, a",
			Value:       "0",
			Usage:       "`ether` to send",
			Destination: &tc.Amount,
		},
		cli.IntFlag{
			Name:        "nonce, n",
			Value:       0,
			Usage:       "transaction nonce for sender",
			Destination: &tc.Nonce,
		},
		cli.IntFlag{
			Name:        "gaslimit, g",
			Value:       42000,
			Usage:       "`gas` limit for the transaction",
			Destination: &tc.Gas,
		},
		cli.IntFlag{
			Name:        "gasprice, p",
			Value:       2,
			Usage:       "gas `price` (in gwei)",
			Destination: &tc.GasPrice,
		},
		cli.StringFlag{
			Name:   "passphrase",
			Value:  "",
			Usage:  "passphrase to unlock account",
			EnvVar: "PASSPHRASE",
		},
		cli.StringFlag{
			Name:        "from, f",
			Value:       "",
			Usage:       "from `address` of the account",
			EnvVar:      "FROM_ADDRESS",
			Destination: &tc.From,
		},
		cli.StringFlag{
			Name:  "keystore, k",
			Value: "./keystore",
			Usage: "`path` to account keystore",
		},
		cli.IntFlag{
			Name:        "chain-id",
			Value:       1,
			Usage:       "ethereum blockchain `id` - mainnet=1, rinkeby=4",
			Destination: &tc.ChainID,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "new-account",
			Usage: "create a new ethereum account in the keystore",
			Action: func(c *cli.Context) error {
				pass := c.String("passphrase")
				if pass == "" {
					pass = askPassphrase("Enter passphrase: ")
				}

				a, err := tc.Keystore.NewAccount(pass)
				if err != nil {
					return err
				}

				fmt.Printf("\n\nNew account created!\n\nAddress: %s\nURL: %s\n", a.Address.Hex(), a.URL)

				return nil
			},
		},
		{
			Name:  "list-accounts",
			Usage: "list ethereum account in the keystore",
			Action: func(c *cli.Context) error {
				for idx, a := range tc.Keystore.Accounts() {
					fmt.Printf("%d) %v\n", idx, a.Address.Hex())
				}
				return nil
			},
		},
	}

	app.Before = func(c *cli.Context) error {
		keystorePath, err := filepath.Abs(c.GlobalString("keystore"))
		if err != nil {
			return err
		}
		fmt.Printf("Using keystore: %s\n\n", keystorePath)
		tc.Keystore = keystore.NewKeyStore(keystorePath, keystore.StandardScryptN, keystore.StandardScryptP)
		return nil
	}

	app.Action = func(c *cli.Context) error {
		return run(&tc)
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func run(tc *TxnContext) error {
	accs := tc.Keystore.Accounts()
	if len(accs) < 1 {
		fmt.Println("Please create an account in the keystore first")
		return nil
	}

	if err := tc.Validate(); err != nil {
		return err
	}

	var (
		a   accounts.Account
		err error
	)
	if tc.From != "" {
		addr := common.HexToAddress(tc.From)
		if !tc.Keystore.HasAddress(addr) {
			return errors.New("from address account not found in keystore")
		}
	} else {
		a, err = askAccount(tc.Keystore.Accounts())
	}
	if err != nil {
		return err
	}

	if tc.Passphrase == "" {
		tc.Passphrase = askPassphrase(fmt.Sprintf("Enter Passphrase (%v): ", a.Address.Hex()))
	}

	tx := tc.Transaction()
	chainID := big.NewInt(int64(tc.ChainID))

	fmt.Println()
	fmt.Println()
	fmt.Println("Transaction Parameters")
	fmt.Println("----------------------")
	fmt.Println("From:      ", a.Address.Hex())
	fmt.Println("To:        ", tx.To().Hex())
	fmt.Println("Amount:    ", tx.Value())
	fmt.Println("Nonce:     ", tx.Nonce())
	fmt.Println("Gas:       ", tx.Gas())
	fmt.Println("Gas Price: ", tx.GasPrice())
	fmt.Println("Data:      ", string(tx.Data()))
	fmt.Println("Chain ID:  ", tc.ChainID)

	fmt.Printf("\nSigning transaction...\n")
	signedTx, err := tc.Keystore.SignTxWithPassphrase(a, tc.Passphrase, tx, chainID)
	if err != nil {
		fmt.Println("Error signing transaction:", err)
		return err
	}
	fmt.Printf("Transaction signing successful!\n")

	b, err := json.MarshalIndent(signedTx, "", "  ")
	if err != nil {
		log.Fatal("Error marshaling JSON:", err)
		return err
	}

	fmt.Println()
	fmt.Println("Signed Transaction JSON")
	fmt.Println("-----------------------")
	fmt.Println(string(b))

	b, err = rlp.EncodeToBytes(signedTx)
	if err != nil {
		fmt.Println("Error encoding RLP:", err)
		return err
	}

	fmt.Println()
	fmt.Println("Raw Transaction")
	fmt.Println("---------------")
	fmt.Printf("%s\n", common.ToHex(b))
	return nil
}

// TxnContext encapsulates command options for signing transactions
type TxnContext struct {
	To       string
	From     string
	Amount   string
	Gas      int
	GasPrice int
	Nonce    int
	Data     []byte

	ChainID    int
	Passphrase string
	Keystore   *keystore.KeyStore
}

// Transaction returns a types.Transaction from the TxnContext
func (ctx *TxnContext) Transaction() *types.Transaction {
	to := common.HexToAddress(ctx.To)
	nonce := uint64(ctx.Nonce)
	amount := toWei(ctx.Amount)
	gasLimit := uint64(ctx.Gas)
	gasPrice := toGwei(ctx.GasPrice)
	data := ctx.Data // Unused for now

	return types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)
}

// Validate @DOC
func (ctx *TxnContext) Validate() error {
	if ctx.To == "" || common.HexToAddress(ctx.To) == ZeroAddress {
		return errors.New(`Missing "to" address`)
	}
	return nil
}

// common.HexToAddress("0x4621E524e6F95A6280b7761BDE3d150101b290F8")

var (
	// BigEther is a pre-coverted big.Float of 1e18
	BigEther = new(big.Float).SetInt64(params.Ether)

	// ZeroAddress is the ethereum zero address
	ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")
)

func toWei(x string) *big.Int {
	n, ok := new(big.Float).SetString(x)
	if !ok {
		log.Fatalf("Can't convert '%s' to wei", x)
	}

	amount := new(big.Float).Mul(n, BigEther)

	wei, acc := amount.Int(nil)
	if acc != 0 {
		fmt.Println("Wei:", wei)
		fmt.Println("Acc:", acc)
		log.Fatalln("Ether value is not accurate", wei)
	}
	return wei
}

func toGwei(x int) *big.Int {
	return new(big.Int).Mul(big.NewInt(int64(x)), big.NewInt(params.Shannon))
}

func askPassphrase(prompt string) string {
	fmt.Printf(prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}
	return string(b)
}

func askAccount(accs []accounts.Account) (accounts.Account, error) {
	var a accounts.Account
	for {
		fmt.Println("Keystore Accounts")
		fmt.Println("-----------------")
		for idx, a := range accs {
			fmt.Printf("%d) %v\n", idx, a.Address.Hex())
		}
		fmt.Print("\nSelect account: ")

		var in string
		if _, err := fmt.Scanln(&in); err != nil {
			fmt.Printf("Error reading from stdin: %s\n", err)
			return a, err
		}

		idx, err := strconv.Atoi(strings.TrimSpace(in))
		if err != nil || idx < 0 || idx >= len(accs) {
			fmt.Println("Please enter a valid account index.")
			continue
		}

		a = accs[idx]
		break
	}
	return a, nil
}
