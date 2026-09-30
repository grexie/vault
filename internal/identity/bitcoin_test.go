package identity

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestBitcoinPSBTSignaturesAndReviewBinding(t *testing.T) {
	key, e := btcec.NewPrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	defer key.Zero()
	for script := range ownScripts(key.PubKey(), &chaincfg.RegressionNetParams) {
		t.Run(scriptName([]byte(script)), func(t *testing.T) {
			fund := wire.NewMsgTx(2)
			fund.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0xffffffff}, []byte{1, 1}, nil))
			fund.AddTxOut(wire.NewTxOut(1000000, []byte(script)))
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fund.TxHash(), Index: 0}, nil, nil))
			tx.AddTxOut(wire.NewTxOut(999000, []byte(script)))
			p, e := psbt.NewFromUnsignedTx(tx)
			if e != nil {
				t.Fatal(e)
			}
			p.Inputs[0].NonWitnessUtxo = fund
			p.Inputs[0].WitnessUtxo = fund.TxOut[0]
			var b bytes.Buffer
			p.Serialize(&b)
			review, e := ReviewBitcoin(b.Bytes(), "regtest", key.PubKey())
			if e != nil || review.Digest == "" {
				t.Fatal("review failed", e)
			}
			signed, e := SignBitcoin(key, b.Bytes(), "regtest")
			if e != nil {
				t.Fatal(e)
			}
			packet, e := psbt.NewFromRawBytes(bytes.NewReader(signed), false)
			if e != nil {
				t.Fatal(e)
			}
			if e = psbt.MaybeFinalizeAll(packet); e != nil {
				t.Fatal(e)
			}
			final, e := psbt.Extract(packet)
			if e != nil {
				t.Fatal(e)
			}
			fetch := txscript.NewCannedPrevOutputFetcher([]byte(script), 1000000)
			hashes := txscript.NewTxSigHashes(final, fetch)
			engine, e := txscript.NewEngine([]byte(script), final, 0, txscript.StandardVerifyFlags, nil, hashes, 1000000, fetch)
			if e != nil {
				t.Fatal(e)
			}
			if e = engine.Execute(); e != nil {
				t.Fatal("independent script verification failed", e)
			}
			final.TxOut[0].Value--
			hashes = txscript.NewTxSigHashes(final, fetch)
			engine, e = txscript.NewEngine([]byte(script), final, 0, txscript.StandardVerifyFlags, nil, hashes, 1000000, fetch)
			if e == nil && engine.Execute() == nil {
				t.Fatal("signature allowed an output mutation")
			}
			p.Inputs[0].SighashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
			b.Reset()
			p.Serialize(&b)
			if _, e = SignBitcoin(key, b.Bytes(), "regtest"); e == nil {
				t.Fatal("uncommitted outputs were signed")
			}
		})
	}
}
func scriptName(script []byte) string {
	switch {
	case txscript.IsPayToTaproot(script):
		return "taproot"
	case txscript.IsPayToWitnessPubKeyHash(script):
		return "segwit"
	default:
		return "legacy"
	}
}
