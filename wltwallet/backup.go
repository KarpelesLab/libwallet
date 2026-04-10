package wltwallet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pjson"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterStatic("Wallet:backup", apiWalletBackup)
	pobj.RegisterStatic("Wallet:restore", apiWalletRestore)
}

type backupDataEntry struct {
	Filename string `json:"filename"`
	Data     string `json:"data"`
}

type legacyWallet struct {
	Id        *xuid.XUID
	Name      string
	Curve     string
	Keys      []*WalletKey
	Pubkey    string
	Chaincode string
	Created   rest.Time
	Updated   rest.Time
}

func (wlt *Wallet) doBackup() ([]*backupDataEntry, error) {
	if len(wlt.Keys) == 0 {
		// refuse to backup a wallet without keys
		return nil, nil
	}
	buf, err := json.Marshal(wlt)
	if err != nil {
		return nil, err
	}

	tmp := &backupDataEntry{
		Filename: "wallet_" + base64.RawURLEncoding.EncodeToString(wlt.Id.UUID[:]) + ".dat",
		Data:     base64.RawURLEncoding.EncodeToString(buf),
	}
	return []*backupDataEntry{tmp}, nil
}

func apiWalletBackup(ctx context.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if wlt := apirouter.GetObject[Wallet](ctx, "Wallet"); wlt != nil {
		// only return for a given wallet
		if len(wlt.Keys) == 0 {
			// refuse to backup a wallet without keys
			return nil, errors.New("wallet has no keys, cannot be backed up")
		}
		buf, err := json.Marshal(wlt)
		if err != nil {
			return nil, err
		}

		tmp := &backupDataEntry{
			Filename: "wallet_" + base64.RawURLEncoding.EncodeToString(wlt.Id.UUID[:]) + ".dat",
			Data:     base64.RawURLEncoding.EncodeToString(buf),
		}
		return []*backupDataEntry{tmp}, nil
	}

	var res []*backupDataEntry
	wlts, err := GetAllWallets(e, nil) // nil to disable paging
	if err != nil {
		return nil, err
	}
	for _, wlt := range wlts {
		tmp, err := wlt.doBackup()
		if err != nil {
			return nil, err
		}
		res = append(res, tmp...)
	}

	return res, err
}

type walletRestoreRequest struct {
	Files     []*backupDataEntry `json:"files"`
	migration bool               // if true, means all the restored backups should be migrated
}

type walletRestoreError struct {
	Filename string
	Message  string
}

type walletRestoreResponse struct {
	Update   bool                  `json:"update"`
	Delete   []string              `json:"delete,omitempty"`
	Errors   []*walletRestoreError `json:"errors,omitempty"`
	Backup   []*backupDataEntry    `json:"backup,omitempty"`
	Restored int                   `json:"restore_count"`
	Existing int                   `json:"existing_count"`
	Missing  int                   `json:"missing_count"`
	checked  map[string]bool
}

func apiWalletRestore(ctx context.Context, in *walletRestoreRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	res := &walletRestoreResponse{
		checked: make(map[string]bool),
	}

	for _, f := range in.Files {
		if strings.HasPrefix(f.Filename, "wallet_") {
			err := restoreSingleWalletFile(e, f.Filename, f.Data, in, res)
			if err != nil {
				errObj := &walletRestoreError{
					Filename: f.Filename,
					Message:  err.Error(),
				}
				res.Errors = append(res.Errors, errObj)
			}
		}
		if f.Filename == "flutter_app_starter__backup.json" || f.Filename == "backup_data.json" {
			err := restoreLegacyWalletFile(ctx, f.Filename, f.Data, res)
			if err != nil {
				errObj := &walletRestoreError{
					Filename: f.Filename,
					Message:  err.Error(),
				}
				res.Errors = append(res.Errors, errObj)
			}
		}
	}

	// run a full backup
	if wlts, err := GetAllWallets(e, nil); err == nil { // nil to disable paging
		for _, wlt := range wlts {
			if _, ok := res.checked[wlt.Id.String()]; ok {
				continue
			}
			res.Missing += 1
			tmp, err := wlt.doBackup()
			if err != nil {
				return nil, err
			}
			res.Backup = append(res.Backup, tmp...)
		}
	}
	return res, nil
}

func restoreSingleWalletFile(e wltintf.Env, filename, data string, req *walletRestoreRequest, res *walletRestoreResponse) error {
	// wallet_<key>.dat
	triggerUpdate := req.migration
	key := strings.TrimPrefix(filename, "wallet_")
	key = strings.TrimSuffix(key, ".dat")
	keyBin, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode key in filename: %w", err)
	}
	// decode value to make sure it is valid
	buf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("failed to decode file body: %w", err)
	}
	var savedWallet *Wallet
	err = pjson.Unmarshal(buf, &savedWallet)
	if err != nil {
		var legacySavedWallet *legacyWallet
		err = pjson.Unmarshal(buf, &legacySavedWallet)
		if err != nil {
			return err
		}
		savedWallet = &Wallet{
			Id:        legacySavedWallet.Id,
			Name:      legacySavedWallet.Name,
			Curve:     legacySavedWallet.Curve,
			Keys:      legacySavedWallet.Keys,
			Pubkey:    legacySavedWallet.Pubkey,
			Chaincode: legacySavedWallet.Chaincode,
			Created:   legacySavedWallet.Created.Time,
			Modified:  legacySavedWallet.Updated.Time,
		}

		// need to trigger an update
		triggerUpdate = true
	}
	// ensure key matches
	if !bytes.Equal(keyBin, savedWallet.Id.UUID[:]) {
		return fmt.Errorf("got filename=%s but inside it was id=%s", filename, savedWallet.Id)
	}
	if len(savedWallet.Keys) == 0 {
		// ignore empty wallet
		return fmt.Errorf("invalid wallet: empty")
	}

	// mark checked now
	res.checked[savedWallet.Id.String()] = true

	// fetch matching wallet from db
	curWallet, err := WalletById(e, savedWallet.Id)
	if err != nil {
		// does not exist in local db → create it
		if triggerUpdate {
			if dat, err := savedWallet.doBackup(); err == nil {
				res.Backup = append(res.Backup, dat...)
			}
		}
		res.Restored += 1
		// trigger creation of account (among other things)
		err = savedWallet.save(e)
		if err != nil {
			return err
		}
		e.Emitter().Emit(context.Background(), "wallet:restored", savedWallet)
		return nil
	}
	// check which wallet is most recent
	if savedWallet.Modified.After(curWallet.Modified) {
		// savedWallet is newer
		if triggerUpdate {
			if dat, err := savedWallet.doBackup(); err == nil {
				res.Backup = append(res.Backup, dat...)
			}
		}
		res.Restored += 1
		return savedWallet.save(e)
	}
	res.Existing += 1
	if triggerUpdate || curWallet.Modified.After(savedWallet.Modified) {
		// the wallet in the backup is old, trigger an update
		res.Update = true
		if dat, err := curWallet.doBackup(); err == nil {
			res.Backup = append(res.Backup, dat...)
		}
	}
	return nil
}

func restoreLegacyWalletFile(ctx context.Context, filename, data string, res *walletRestoreResponse) error {
	var t []*backupDataEntry
	err := json.Unmarshal([]byte(data), &t)
	if err != nil {
		return err
	}
	_, err = apiWalletRestore(ctx, &walletRestoreRequest{t, true})
	if err != nil {
		return err
	}
	res.Update = true
	res.Delete = append(res.Delete, filename)
	return nil
}
