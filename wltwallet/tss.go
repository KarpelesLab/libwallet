package wltwallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/KarpelesLab/libwallet/wltcrash"
	"github.com/KarpelesLab/pobj"
	"github.com/ModChain/tss-lib/v2/ecdsa/keygen"
	"github.com/ModChain/tss-lib/v2/tss"
)

type tssPartyUpdateOnly interface {
	Start() error
	UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (ok bool, err error)
}

func init() {
	pobj.RegisterStatic("TSS:genParams", tssGenParams)
}

func tssGenParams(ctx context.Context) (any, error) {
	preParams, _ := keygen.GeneratePreParamsWithContext(ctx)
	res, _ := json.Marshal(preParams)
	return base64.RawURLEncoding.EncodeToString(res), nil
}

func tssRouter(ctx context.Context, parties map[string]tssPartyUpdateOnly, outCh chan tss.Message) {
	defer func() {
		wltcrash.Log(ctx, recover(), "tss router")
	}()
	for msg := range outCh {
		log.Printf("msg: %s", msg)
		data, routing, err := msg.WireBytes()
		if err != nil {
			log.Printf("error: %s", err)
			continue
		}
		if routing.To == nil {
			// when `nil` the message should be broadcast to all parties
			for _, p := range parties {
				go func(p tssPartyUpdateOnly) {
					p.UpdateFromBytes(data, routing.From, true)
					//log.Printf("%s waiting for %v", p, p.WaitingFor())
				}(p)
			}
		} else {
			for _, to := range routing.To {
				p, ok := parties[to.Id]
				if !ok {
					log.Printf("tss: id not found: %s", to.Id)
					continue
				}
				go func(p tssPartyUpdateOnly) {
					ok, err := p.UpdateFromBytes(data, msg.GetFrom(), msg.IsBroadcast())
					if err != nil {
						log.Printf("update from bytes error: %s", err)
					} else if !ok {
						log.Printf("update from bytes not ok")
					}
					//log.Printf("%s waiting for %v", p, p.WaitingFor())
				}(p)
			}
		}
	}
}
