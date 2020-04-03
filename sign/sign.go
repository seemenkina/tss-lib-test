package sign

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/seemenkina/tss-lib-test/utils"
)

func NewSigning(msg *big.Int) common.SignatureData {
	utils.SetUp("info")
	tss.SetCurve(elliptic.P256())

	threshold := utils.TestThreshold
	var output common.SignatureData

	// PHASE: load keygen fixtures
	keys, signPIDs, err := utils.LoadData(utils.TestThreshold+1, utils.TestParticipants)
	if err != nil {
		common.Logger.Errorf("should load keygen fixtures, %s", err)
	}
	if utils.TestThreshold+1 != len(keys) && utils.TestThreshold+1 != len(signPIDs) {
		common.Logger.Errorf("should be equal")
	}

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := signing.NewLocalParty(msg, params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			if atomic.AddInt32(&ended, 1) == int32(len(signPIDs)) {
				common.Logger.Infof("Done. Received save data from %d participants", ended)
				output = save
				break signing
			}
		}
	}
	return output
}
