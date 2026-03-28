package wltwallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

type spotParty struct {
	info    *walletSignReshareInit
	spot    *spotlib.Client
	sid     string
	peer    string
	parties map[string]tssPartyUpdateOnly
	stOnce  sync.Once
	stErr   error
}

func (s *spotParty) Start() error {
	s.stOnce.Do(func() {
		// setup handler
		s.spot.SetHandler(s.sid, s.messageHandler)

		peerCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// locate a live peer
		peer, err := selectPeer(peerCtx, s.spot)
		if err != nil {
			s.stErr = fmt.Errorf("failed to select peer: %w", err)
			return
		}
		log.Printf("selected peer: %s", peer)
		s.peer = peer

		// initalize session
		buf, err := json.Marshal(s.info)
		if err != nil {
			s.stErr = err
			return
		}

		_, err = s.spot.QueryTimeout(15*time.Second, peer+"/walletsign/"+s.sid+"/init", buf)
		if err != nil {
			s.stErr = fmt.Errorf("failed to init remote: %w", err)
			return
		}
		log.Printf("remote initialized, ready for signature")
	})
	return s.stErr
}

func (s *spotParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, error) {
	// * msg.Sender is `<spot.id>/<query_key>` if init, or `<spot.id>/<sid>/<dest_id>`
	// * msg.Recipient is `<id>/walletsign/<sid>[/<type>]`
	tgt := s.peer + "/walletsign/" + s.sid
	if isBroadcast {
		tgt += "/broadcast"
	} else {
		tgt += "/single"
	}
	sender := "/" + s.sid + "/" + from.Id

	log.Printf("sending message from %s to %s broadcast=%v", sender, tgt, isBroadcast)

	err := s.spot.SendToWithFrom(context.Background(), tgt, wireBytes, sender)

	return true, err
}

func (s *spotParty) messageHandler(msg *spotproto.Message) ([]byte, error) {
	if !msg.IsEncrypted() {
		// only process messages that were end to end encrypted
		return nil, nil
	}
	if len(msg.Body) == 0 {
		// ignore empty body
		return nil, nil
	}

	// * msg.Sender is `<spot.id>/walletsign/<sid>[/broadcast]`
	// * msg.Recipient is `<spot.id>/<sid>/all` (if all) or `<spot.id>/<sid>/<partyId>` (individual party)
	splitSender := strings.Split(msg.Sender, "/")
	isBroadcast := false
	// k.5tZz33ahQLmjJF0ZBYCfqPE63Fj7AChm5u7Ne9N4kYw/walletsign/elws-jmsori-l66r-dv5p-54mv-zoz62sea:elwsv-bzyvhx-rt3r-gv3b-xcnc-m44enxeu/broadcast
	if len(splitSender) >= 4 && splitSender[3] == "broadcast" {
		isBroadcast = true
	}
	//log.Printf("handle message %s → %s broadcast=%v\n%s", msg.Sender, msg.Recipient, isBroadcast, hex.Dump(msg.Body))

	splitRecipient := strings.Split(msg.Recipient, "/")
	if len(splitRecipient) < 3 {
		// should be at least 3
		log.Printf("invalid recipient on msg")
		return nil, nil
	}
	dstParty := splitRecipient[2]
	if dstParty == "all" {
		log.Printf("*** broadcast msg")
		for _, p := range s.parties {
			ok, err := p.UpdateFromBytes(msg.Body, s.info.Name, true)
			if err == nil && !ok {
				err = errors.New("false returned")
			}
			if err != nil {
				log.Printf("failed to update peer: %s", err)
			}
		}
	} else {
		if p, ok := s.parties[dstParty]; ok {
			ok, err := p.UpdateFromBytes(msg.Body, s.info.Name, isBroadcast)
			if err == nil && !ok {
				err = errors.New("false returned")
			}
			if err != nil {
				log.Printf("failed to update peer: %s", err)
			}
			return nil, nil
		}
		log.Printf("failed to handle message to %s", dstParty)
	}

	return nil, nil
}
