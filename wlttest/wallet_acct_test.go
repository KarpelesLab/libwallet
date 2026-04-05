package wlttest

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/portablesql/psql"
)

// TestWalletAccountLifecycle tests the full lifecycle of wallets and accounts
// using the new temporary environment
func TestWalletAccountLifecycle(t *testing.T) {
	// Create a temporary environment for testing
	tempEnv, err := wltbase.InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer wltbase.CleanupTempEnv(tempEnv)

	env, ok := tempEnv.(wltintf.Env)
	if !ok {
		t.Fatalf("Temporary environment is not a valid wltintf.Env")
	}

	// Step 1: Verify no wallets exist initially
	if wltwallet.HasWallet(env) {
		t.Errorf("Expected no wallets in a fresh environment")
	}

	// Step 2: Create a wallet with 3 plain keys using NewWalletForTesting
	wallet, err := wltwallet.NewWalletForTesting("Test Wallet", "")
	if err != nil {
		t.Fatalf("Failed to create test wallet: %v", err)
	}

	t.Logf("Created wallet with %d keys", len(wallet.Keys))

	// Save the wallet keys first
	for _, key := range wallet.Keys {
		err = psql.Replace(env, key)
		if err != nil {
			t.Fatalf("Failed to save wallet key: %v", err)
		}
	}

	// Then save the wallet
	err = psql.Replace(env, wallet)
	if err != nil {
		t.Fatalf("Failed to save wallet: %v", err)
	}

	// Step 3: Verify wallet was created successfully
	if !wltwallet.HasWallet(env) {
		t.Errorf("Expected to have at least one wallet after creation")
	}

	// Step 4: Retrieve the wallet
	retrievedWallets, err := psql.Fetch[wltwallet.Wallet](env, nil)
	if err != nil {
		t.Fatalf("Failed to get wallets: %v", err)
	}
	if len(retrievedWallets) != 1 {
		t.Fatalf("Expected 1 wallet, got %d", len(retrievedWallets))
	}
	retrievedWallet := retrievedWallets[0]

	// Step 5: Load wallet keys since DB doesn't automatically load related entities
	if len(retrievedWallet.Keys) == 0 {
		t.Log("Loading wallet keys from database")

		keys, err := psql.Fetch[wltwallet.WalletKey](env, map[string]any{"Wallet": retrievedWallet.Id.String()})
		if err != nil {
			t.Fatalf("Failed to load wallet keys: %v", err)
		}

		if len(keys) != 3 {
			t.Errorf("Expected 3 wallet keys, got %d", len(keys))
		}

		retrievedWallet.Keys = keys
	}

	// Step 6: Verify no accounts exist initially
	if wltacct.HasAccount(env) {
		t.Errorf("Expected no accounts in a fresh environment")
	}

	// Step 7: Create an Ethereum account
	// Account creation should succeed with our properly initialized wallet
	t.Log("Creating Ethereum account")
	account, err := wltacct.CreateAccount(env, retrievedWallet, "Test Account", "ethereum", 0)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Step 8: Verify account was created successfully
	if !wltacct.HasAccount(env) {
		t.Errorf("Expected to have at least one account after creation")
	}

	// Step 9: Test account properties
	if account.Address == "" {
		t.Errorf("Expected account to have an address")
	}

	if account.URI == "" {
		t.Errorf("Expected account to have a URI")
	}

	t.Logf("Account address: %s", account.Address)
	t.Logf("Account URI: %s", account.URI)

	// Create a second account
	var account2 *wltacct.Account
	account2, err = wltacct.CreateAccount(env, retrievedWallet, "Test Account 2", "ethereum", 1)
	if err != nil {
		t.Fatalf("Failed to create second account: %v", err)
	}

	// Verify the accounts have different addresses
	if account2.Address == account.Address {
		t.Errorf("Expected different addresses for different account indices")
	}

	// Test account update
	updatedName := "Updated Account Name"
	originalName := account.Name
	account.Name = updatedName

	err = psql.Replace(env, account)
	if err != nil {
		t.Fatalf("Failed to update account: %v", err)
	}

	// Retrieve the account again to verify update
	updatedAccount, err := psql.Get[wltacct.Account](env, map[string]any{"Id": account.Id.String()})
	if err != nil {
		t.Fatalf("Failed to find updated account: %v", err)
	}

	if updatedAccount.Name != updatedName {
		t.Errorf("Expected account name '%s', got '%s'", updatedName, updatedAccount.Name)
	} else {
		t.Logf("Successfully updated account name from '%s' to '%s'", originalName, updatedAccount.Name)
	}

	// Test account deletion
	_, err = psql.ForceDelete[wltacct.Account](env, map[string]any{"Id": account2.Id})
	if err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}

	// Verify account was deleted
	_, err = psql.Get[wltacct.Account](env, map[string]any{"Id": account2.Id.String()})
	if err == nil {
		t.Errorf("Account should have been deleted but was still found")
	} else {
		t.Log("Successfully deleted account")
	}
}
