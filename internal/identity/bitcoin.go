package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BitcoinNetwork(name string) (*chaincfg.Params, error) {
	switch name {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet":
		return &chaincfg.TestNet3Params, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	}
	return nil, errors.New("explicit Bitcoin network must be mainnet, testnet, signet, or regtest")
}
func BitcoinKey(raw string, network string) (*btcec.PrivateKey, error) {
	params, err := BitcoinNetwork(network)
	if err != nil {
		return nil, err
	}
	wif, err := btcutil.DecodeWIF(raw)
	if err != nil || !wif.IsForNet(params) || !wif.CompressPubKey {
		return nil, errors.New("a compressed WIF key for the selected Bitcoin network is required")
	}
	return wif.PrivKey, nil
}
func BitcoinAddress(pub *btcec.PublicKey, network string) (string, error) {
	params, err := BitcoinNetwork(network)
	if err != nil {
		return "", err
	}
	a, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), params)
	if err != nil {
		return "", err
	}
	return a.EncodeAddress(), nil
}
func ownScripts(pub *btcec.PublicKey, params *chaincfg.Params) map[string]string {
	out := map[string]string{}
	legacy, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), params)
	segwit, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), params)
	tr, _ := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)), params)
	for _, a := range []btcutil.Address{legacy, segwit, tr} {
		s, _ := txscript.PayToAddrScript(a)
		out[string(s)] = a.EncodeAddress()
	}
	return out
}

func decodePSBT(raw []byte) (*psbt.Packet, *txscript.MultiPrevOutFetcher, int64, int64, error) {
	if len(raw) > 4*1024*1024 {
		return nil, nil, 0, 0, errors.New("PSBT exceeds size limit")
	}
	reader := bytes.NewReader(raw)
	p, err := psbt.NewFromRawBytes(reader, false)
	if err != nil || reader.Len() != 0 {
		return nil, nil, 0, 0, errors.New("invalid PSBT")
	}
	if len(p.Inputs) == 0 || len(p.Inputs) > 200 || len(p.Outputs) == 0 || len(p.Outputs) > 200 {
		return nil, nil, 0, 0, errors.New("PSBT input/output count exceeds limit")
	}
	fetch := txscript.NewMultiPrevOutFetcher(nil)
	var inTotal, outTotal int64
	const maxMoney int64 = 21000000 * 100000000
	seen := map[wire.OutPoint]bool{}
	for i, in := range p.Inputs {
		point := p.UnsignedTx.TxIn[i].PreviousOutPoint
		if seen[point] {
			return nil, nil, 0, 0, errors.New("duplicate transaction input")
		}
		seen[point] = true
		var utxo *wire.TxOut
		if in.NonWitnessUtxo != nil {
			if in.NonWitnessUtxo.TxHash() != point.Hash || uint64(point.Index) >= uint64(len(in.NonWitnessUtxo.TxOut)) {
				return nil, nil, 0, 0, errors.New("previous transaction does not match input")
			}
			utxo = in.NonWitnessUtxo.TxOut[point.Index]
		}
		if in.WitnessUtxo != nil {
			if utxo != nil && (utxo.Value != in.WitnessUtxo.Value || !bytes.Equal(utxo.PkScript, in.WitnessUtxo.PkScript)) {
				return nil, nil, 0, 0, errors.New("conflicting previous outputs")
			}
			utxo = in.WitnessUtxo
		}
		if utxo == nil || utxo.Value < 0 || utxo.Value > maxMoney || inTotal > maxMoney-utxo.Value {
			return nil, nil, 0, 0, errors.New("missing or invalid previous output value")
		}
		// SIGHASH_ALL/default bind every output. Partial-commitment signatures can
		// change the approved transaction after review and are not accepted.
		if in.SighashType != 0 && in.SighashType != txscript.SigHashAll {
			return nil, nil, 0, 0, errors.New("only SIGHASH_ALL or Taproot DEFAULT is supported")
		}
		inTotal += utxo.Value
		fetch.AddPrevOut(point, utxo)
	}
	for _, out := range p.UnsignedTx.TxOut {
		if out.Value < 0 || out.Value > maxMoney || outTotal > maxMoney-out.Value {
			return nil, nil, 0, 0, errors.New("invalid output value")
		}
		outTotal += out.Value
	}
	if inTotal < outTotal {
		return nil, nil, 0, 0, errors.New("outputs exceed inputs")
	}
	return p, fetch, inTotal, outTotal, nil
}

func ReviewBitcoin(raw []byte, network string, pub *btcec.PublicKey) (Review, error) {
	params, err := BitcoinNetwork(network)
	if err != nil {
		return Review{}, err
	}
	p, fetch, inTotal, outTotal, err := decodePSBT(raw)
	if err != nil {
		return Review{}, err
	}
	r := Review{Kind: "bitcoin", Title: "Sign Bitcoin transaction", Fields: []Field{{"Network", network}, {"Transaction version", fmt.Sprint(p.UnsignedTx.Version)}, {"Lock time", fmt.Sprint(p.UnsignedTx.LockTime)}}, Warnings: []string{"UTXO values come from the supplied PSBT. Availability and confirmations have not been checked against a Bitcoin node."}}
	known := map[string]string{}
	if pub != nil {
		known = ownScripts(pub, params)
	}
	for i, in := range p.UnsignedTx.TxIn {
		utxo := fetch.FetchPrevOutput(in.PreviousOutPoint)
		r.Fields = append(r.Fields, Field{fmt.Sprintf("Input %d", i+1), in.PreviousOutPoint.String() + " · " + formatUnits(big.NewInt(utxo.Value), 8) + " BTC"})
		if in.Sequence < 0xfffffffe {
			r.Warnings = append(r.Warnings, "Replace-by-fee is enabled by an input sequence.")
		}
	}
	for i, out := range p.UnsignedTx.TxOut {
		_, addrs, _, e := txscript.ExtractPkScriptAddrs(out.PkScript, params)
		destination := "Script 0x" + hex.EncodeToString(out.PkScript)
		if e == nil && len(addrs) == 1 {
			destination = addrs[0].EncodeAddress()
		}
		label := fmt.Sprintf("Output %d", i+1)
		if _, ok := known[string(out.PkScript)]; ok {
			label += " (returns to this identity)"
		}
		r.Fields = append(r.Fields, Field{label, formatUnits(big.NewInt(out.Value), 8) + " BTC → " + destination})
	}
	fee := inTotal - outTotal
	r.Fields = append(r.Fields, Field{"Total input", formatUnits(big.NewInt(inTotal), 8) + " BTC"}, Field{"Total output", formatUnits(big.NewInt(outTotal), 8) + " BTC"}, Field{"Network fee", fmt.Sprint(fee) + " sat"})
	if fee > 1000000 || fee > outTotal/10 {
		r.Warnings = append(r.Warnings, "High fee: review the exact input and output amounts carefully.")
	}
	var buf bytes.Buffer
	p.UnsignedTx.Serialize(&buf)
	digest := sha256.Sum256(raw)
	r.Digest = hex.EncodeToString(digest[:])
	r.Raw = hex.EncodeToString(buf.Bytes())
	return r, nil
}

// SignBitcoin adds signatures only for inputs controlled by this single key and
// returns a PSBT. It never finalizes, broadcasts, or signs uncommitted outputs.
func SignBitcoin(key *btcec.PrivateKey, raw []byte, network string) ([]byte, error) {
	params, err := BitcoinNetwork(network)
	if err != nil {
		return nil, err
	}
	p, fetch, _, _, err := decodePSBT(raw)
	if err != nil {
		return nil, err
	}
	scripts := ownScripts(key.PubKey(), params)
	sigHashes := txscript.NewTxSigHashes(p.UnsignedTx, fetch)
	count := 0
	for i := range p.Inputs {
		in := &p.Inputs[i]
		out := fetch.FetchPrevOutput(p.UnsignedTx.TxIn[i].PreviousOutPoint)
		if _, ok := scripts[string(out.PkScript)]; !ok {
			continue
		}
		if len(in.FinalScriptSig) > 0 || len(in.FinalScriptWitness) > 0 {
			return nil, errors.New("selected input already finalized")
		}
		if len(in.RedeemScript) > 0 || len(in.WitnessScript) > 0 || len(in.TaprootMerkleRoot) > 0 || len(in.TaprootLeafScript) > 0 {
			return nil, errors.New("script-path signing is unsupported")
		}
		hashType := in.SighashType
		var sig []byte
		if txscript.IsPayToTaproot(out.PkScript) {
			if len(in.TaprootInternalKey) > 0 && !bytes.Equal(in.TaprootInternalKey, schnorr.SerializePubKey(key.PubKey())) {
				return nil, errors.New("Taproot internal key mismatch")
			}
			sig, err = txscript.RawTxInTaprootSignature(p.UnsignedTx, sigHashes, i, out.Value, out.PkScript, nil, hashType, key)
			if err != nil {
				return nil, err
			}
			in.TaprootKeySpendSig = sig
		} else {
			if hashType == 0 {
				hashType = txscript.SigHashAll
			}
			in.SighashType = hashType
			if txscript.IsPayToWitnessPubKeyHash(out.PkScript) {
				legacy, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(key.PubKey().SerializeCompressed()), params)
				code, _ := txscript.PayToAddrScript(legacy)
				sig, err = txscript.RawTxInWitnessSignature(p.UnsignedTx, sigHashes, i, out.Value, code, hashType, key)
			} else {
				if in.NonWitnessUtxo == nil {
					return nil, errors.New("legacy input requires the complete previous transaction")
				}
				sig, err = txscript.RawTxInSignature(p.UnsignedTx, i, out.PkScript, hashType, key)
				// A legacy input is finalized from the full previous transaction.
				// Remove a redundant witness UTXO after decodePSBT has checked that
				// both representations agree; PSBT consumers otherwise treat it as
				// a witness input and cannot finalize a valid P2PKH signature.
				in.WitnessUtxo = nil
			}
			if err != nil {
				return nil, err
			}
			for _, old := range in.PartialSigs {
				if bytes.Equal(old.PubKey, key.PubKey().SerializeCompressed()) {
					return nil, errors.New("selected input already signed")
				}
			}
			in.PartialSigs = append(in.PartialSigs, &psbt.PartialSig{PubKey: key.PubKey().SerializeCompressed(), Signature: sig})
		}
		count++
	}
	if count == 0 {
		return nil, errors.New("PSBT contains no inputs belonging to the selected identity")
	}
	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
