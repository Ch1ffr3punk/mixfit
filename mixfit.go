package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/crooks/yamn/crandom"
	"github.com/crooks/yamn/keymgr"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/nacl/box"
)

const (
	version        = "0.2.7"
	maxChainLength = 10
	headerBytes    = 256
	encHeadBytes   = 160
	encDataBytes   = 64
	headersBytes   = headerBytes * maxChainLength
	bodyBytes      = 17920
	messageBytes   = headersBytes + bodyBytes
	base64LineWrap = 64
)

var (
	PubRing *keymgr.Pubring
	flags   struct {
		Chain string
	}
	haveStats bool
)

func main() {
	flag.StringVar(&flags.Chain, "l", "", "Remailer chain (*,*,*... up to 10)")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -l remailer1,remailer2... < message.txt > outfile.txt\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	
	flag.Parse()

        pubringFile := "pubring.mix"
	mlist2File := "mlist2.txt"

	if _, err := os.Stat(pubringFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %s not found in current directory\n", pubringFile)
		os.Exit(1)
	}

	PubRing = keymgr.NewPubring(pubringFile, mlist2File)
	if err := PubRing.ImportPubring(); err != nil {
		fmt.Fprintf(os.Stderr, "Error importing pubring: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stat(mlist2File); err == nil {
		if err := PubRing.ImportStats(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not import stats: %v\n", err)
		} else {
			haveStats = true
		}
	}

	plain, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	if len(plain) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No input received from stdin")
		os.Exit(1)
	}

	if len(plain) > bodyBytes {
		fmt.Fprintf(os.Stderr, "Error: Message too large. Maximum size is %d bytes, got %d bytes\n", bodyBytes, len(plain))
		os.Exit(1)
	}

	mixprep(plain)
}

func mixprep(plain []byte) {
	inChain := strings.Split(flags.Chain, ",")
	
	if len(inChain) == 0 {
		fmt.Fprintln(os.Stderr, "Error: empty chain")
		os.Exit(1)
	}

	for _, hop := range inChain {
		if hop == "*" && !haveStats {
			fmt.Fprintln(os.Stderr, "Error: random remailers (*) require stats file (mlist2.txt)")
			os.Exit(1)
		}
	}

	final := newSlotFinal()
	final.setNumChunks(1)
	final.setBodyBytes(len(plain))

	var chain []string
	inChainFunc := append(inChain[:0:0], inChain...)
	
	chain, err := makeChain(inChainFunc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating chain: %v\n", err)
		os.Exit(1)
	}

	if len(chain) != len(inChain) {
		fmt.Fprintf(os.Stderr, "Error: chain length mismatch\n")
		os.Exit(1)
	}

	_ = chain[0]
	fmt.Fprintf(os.Stderr, "Chain: %s\n", strings.Join(chain, ","))
	
	yamnMsg := encodeMsg(plain, chain, *final)
	
	armor(os.Stdout, yamnMsg)
	
	fmt.Fprintln(os.Stderr, "YAMN payload created successfully")
}

func makeChain(inChain []string) (outChain []string, err error) {
	if len(inChain) > maxChainLength {
		fmt.Fprintf(os.Stderr, "%d hops exceeds maximum of %d\n", len(inChain), maxChainLength)
		os.Exit(1)
	}

	outChain = make([]string, 0, len(inChain))
	numHops := len(inChain)
	
	var candidates []string
	var hop string
	
	for {
		hop = popstr(&inChain)
		if hop == "*" {
			if len(outChain) == 0 {
				// Exit node (last hop in chain)
				candidates = PubRing.Candidates(2, 60, 99.0, true)
			} else {
				// Intermediate node
				candidates = PubRing.Candidates(2, 60, 98.0, false)
			}
			
			if len(candidates) == 0 {
				// Relax criteria if no candidates found
				if len(outChain) == 0 {
					candidates = PubRing.Candidates(0, 480, 0, true)
				} else {
					candidates = PubRing.Candidates(0, 480, 0, false)
				}
			}
			
			if len(candidates) == 0 {
				fmt.Fprintln(os.Stderr, "Error: no remailers available to build random chain link")
				os.Exit(1)
			} else if len(candidates) == 1 {
				hop = candidates[0]
				fmt.Fprintf(os.Stderr, "Warning: Only one remailer (%s) meets chain criteria\n", hop)
			} else {
				// Random selection from candidates
				hop = candidates[crandom.RandomInt(len(candidates))]
			}
		} else {
			remailer, err := PubRing.Get(hop)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			hop = remailer.Address
		}
		
		outChain = append([]string{hop}, outChain...)
		
		if len(inChain) == 0 {
			break
		}
	}
	
	if len(outChain) != numHops {
		fmt.Fprintln(os.Stderr, "Error: constructed chain length doesn't match input chain length")
		os.Exit(1)
	}
	return outChain, nil
}

// IsMemberStr tests for the membership of a string in a slice
func IsMemberStr(s string, slice []string) bool {
	for _, n := range slice {
		if n == s {
			return true
		}
	}
	return false
}

// distanceCriteria enforces user-defined minimal distance criteria
func distanceCriteria(addresses, dist []string) (c []string) {
	for _, addy := range addresses {
		if IsMemberStr(addy, dist) {
			// Excluded due to distance
			continue
		}
		c = append(c, addy)
	}
	return
}

type slotFinal struct {
	aesIV          []byte
	chunkNum       uint8
	numChunks      uint8
	messageID      []byte
	packetID       []byte
	gotBodyBytes   bool
	bodyBytes      int
	deliveryMethod uint8
}

func newSlotFinal() *slotFinal {
	return &slotFinal{
		aesIV:          crandom.Randbytes(16),
		chunkNum:       1,
		numChunks:      1,
		messageID:      crandom.Randbytes(16),
		packetID:       crandom.Randbytes(16),
		gotBodyBytes:   false,
		deliveryMethod: 0,
	}
}

func (f *slotFinal) setNumChunks(n int) {
	f.numChunks = uint8(n)
}

func (f *slotFinal) setBodyBytes(length int) {
	if length > bodyBytes {
		fmt.Fprintf(os.Stderr, "Error: body (%d bytes) exceeds maximum (%d bytes)\n", length, bodyBytes)
		os.Exit(1)
	}
	f.bodyBytes = length
	f.gotBodyBytes = true
}

func (f *slotFinal) encode() []byte {
	if !f.gotBodyBytes {
		fmt.Fprintln(os.Stderr, "Error: cannot encode slot final before body length is defined")
		os.Exit(1)
	}
	buf := new(bytes.Buffer)
	buf.Write(f.aesIV)
	buf.WriteByte(f.chunkNum)
	buf.WriteByte(f.numChunks)
	buf.Write(f.messageID)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(f.bodyBytes))
	buf.Write(tmp)
	buf.WriteByte(f.deliveryMethod)
	if buf.Len() != 39 {
		fmt.Fprintf(os.Stderr, "Error: incorrect buffer length: Wanted=39, Got=%d\n", buf.Len())
		os.Exit(1)
	}
	buf.WriteString(strings.Repeat("\x00", encDataBytes-buf.Len()))
	return buf.Bytes()
}

type slotData struct {
	version       uint8
	packetType    uint8
	protocol      uint8
	packetID      []byte
	gotAesKey     bool
	aesKey        []byte
	timestamp     []byte
	gotPacketInfo bool
	packetInfo    []byte
	gotTagHash    bool
	tagHash       []byte
}

func newSlotData() *slotData {
	timestamp := make([]byte, 2)
	ts := time.Now().UTC().Unix() / 86400
	ts -= int64(crandom.Dice() % 4)
	binary.LittleEndian.PutUint16(timestamp, uint16(ts))
	return &slotData{
		version:       2,
		packetType:    0,
		protocol:      0,
		packetID:      crandom.Randbytes(16),
		gotAesKey:     false,
		aesKey:        make([]byte, 32),
		timestamp:     timestamp,
		gotPacketInfo: false,
		gotTagHash:    false,
		tagHash:       make([]byte, 32),
	}
}

func (head *slotData) setExit() {
	head.packetType = 1
}

func (head *slotData) setAesKey(key []byte) {
	if len(key) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid key length. Expected=32, Got=%d\n", len(key))
		os.Exit(1)
	}
	copy(head.aesKey, key)
	head.gotAesKey = true
}

func (head *slotData) setPacketID(id []byte) {
	if len(id) != 16 {
		fmt.Fprintf(os.Stderr, "Error: invalid packet ID length. Expected=16, Got=%d\n", len(id))
		os.Exit(1)
	}
	copy(head.packetID, id)
}

func (head *slotData) setTagHash(hash []byte) {
	if len(hash) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid hash length. Expected=32, Got=%d\n", len(hash))
		os.Exit(1)
	}
	copy(head.tagHash, hash)
	head.gotTagHash = true
}

func (head *slotData) setPacketInfo(ei []byte) {
	if len(ei) != encDataBytes {
		fmt.Fprintf(os.Stderr, "Error: invalid packet info length. Expected=%d, Got=%d\n", encDataBytes, len(ei))
		os.Exit(1)
	}
	head.gotPacketInfo = true
	head.packetInfo = ei
}

func (head *slotData) encode() []byte {
	if !head.gotAesKey {
		fmt.Fprintln(os.Stderr, "Error: AES key not specified")
		os.Exit(1)
	}
	if !head.gotPacketInfo {
		fmt.Fprintln(os.Stderr, "Error: packet info not defined")
		os.Exit(1)
	}
	if !head.gotTagHash {
		fmt.Fprintln(os.Stderr, "Error: anti-tag hash not defined")
		os.Exit(1)
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(head.version)
	buf.WriteByte(head.packetType)
	buf.WriteByte(head.protocol)
	buf.Write(head.packetID)
	buf.Write(head.aesKey)
	buf.Write(head.timestamp)
	buf.Write(head.packetInfo)
	buf.Write(head.tagHash)
	if buf.Len() != 149 {
		fmt.Fprintf(os.Stderr, "Error: incorrect buffer length: Expected=149, Got=%d\n", buf.Len())
		os.Exit(1)
	}
	buf.WriteString(strings.Repeat("\x00", encHeadBytes-buf.Len()))
	return buf.Bytes()
}

type encodeHeader struct {
	gotRecipient   bool
	recipientKeyID []byte
	recipientPK    [32]byte
}

func newEncodeHeader() *encodeHeader {
	return &encodeHeader{
		gotRecipient:   false,
		recipientKeyID: make([]byte, 16),
	}
}

func (h *encodeHeader) setRecipient(recipientKeyID, recipientPK []byte) {
	if len(recipientKeyID) != 16 {
		fmt.Fprintf(os.Stderr, "Error: invalid key ID length. Expected=16, Got=%d\n", len(recipientKeyID))
		os.Exit(1)
	}
	if len(recipientPK) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid public key length. Expected=32, Got=%d\n", len(recipientPK))
		os.Exit(1)
	}
	copy(h.recipientPK[:], recipientPK)
	copy(h.recipientKeyID, recipientKeyID)
	h.gotRecipient = true
}

func (h *encodeHeader) encode(encHead []byte) []byte {
	if !h.gotRecipient {
		fmt.Fprintln(os.Stderr, "Error: header encode without defining recipient")
		os.Exit(1)
	}
	if len(encHead) != encHeadBytes {
		fmt.Fprintf(os.Stderr, "Error: invalid encrypted header length. Expected=%d, Got=%d\n", encHeadBytes, len(encHead))
		os.Exit(1)
	}

	senderPK, senderSK, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}
	var nonce [24]byte
	copy(nonce[:], crandom.Randbytes(24))
	buf := new(bytes.Buffer)
	buf.Write(h.recipientKeyID)
	buf.Write(senderPK[:])
	buf.Write(nonce[:])
	buf.Write(box.Seal(nil, encHead, &nonce, &h.recipientPK, senderSK))
	if buf.Len() != 248 {
		fmt.Fprintf(os.Stderr, "Error: incorrect buffer length: Expected=248, Got=%d\n", buf.Len())
		os.Exit(1)
	}
	buf.Write(crandom.Randbytes(headerBytes - buf.Len()))
	return buf.Bytes()
}

type encMessage struct {
	gotPayload       bool
	payload          []byte
	plainLength      int
	keys             [maxChainLength - 1][]byte
	ivs              [maxChainLength - 1][]byte
	chainLength      int
	intermediateHops int
	padHeaders       int
	padBytes         int
}

func newEncMessage() *encMessage {
	return &encMessage{
		gotPayload:  false,
		payload:     make([]byte, messageBytes),
		chainLength: 0,
	}
}

func (m *encMessage) getPayload() []byte {
	return m.payload
}

func (m *encMessage) setChainLength(chainLength int) {
	if chainLength > maxChainLength {
		fmt.Fprintf(os.Stderr, "Error: chain length (%d) exceeds maximum (%d)\n", chainLength, maxChainLength)
		os.Exit(1)
	}
	if chainLength <= 0 {
		fmt.Fprintln(os.Stderr, "Error: chain length cannot be negative or zero")
		os.Exit(1)
	}
	m.chainLength = chainLength
	m.intermediateHops = chainLength - 1
	m.padHeaders = maxChainLength - m.chainLength
	m.padBytes = m.padHeaders * headerBytes
	copy(m.payload, crandom.Randbytes(m.padBytes))
	for n := 0; n < m.intermediateHops; n++ {
		m.keys[n] = crandom.Randbytes(32)
		m.ivs[n] = crandom.Randbytes(12)
	}
}

func (m *encMessage) setPlainText(plain []byte) (plainLength int) {
	plainLength = len(plain)
	if plainLength > bodyBytes {
		fmt.Fprintf(os.Stderr, "Error: payload (%d) exceeds max length (%d)\n", plainLength, bodyBytes)
		os.Exit(1)
	}
	copy(m.payload[headersBytes:], plain)
	m.gotPayload = true
	return
}

func (m *encMessage) getIntermediateHops() int {
	if m.chainLength == 0 {
		fmt.Fprintln(os.Stderr, "Error: cannot get hop count. Chain length is not defined")
		os.Exit(1)
	}
	return m.intermediateHops
}

func (m *encMessage) getKey(intermediateHop int) []byte {
	if m.chainLength == 0 {
		fmt.Fprintln(os.Stderr, "Error: cannot get a Key until the chain length is defined")
		os.Exit(1)
	}
	if intermediateHop >= m.intermediateHops {
		fmt.Fprintf(os.Stderr, "Error: requested key for hop (%d) exceeds array length (%d)\n", intermediateHop, m.intermediateHops)
		os.Exit(1)
	}
	return m.keys[intermediateHop]
}

func (m *encMessage) getPartialIV(intermediateHop int) []byte {
	if intermediateHop > m.intermediateHops {
		fmt.Fprintf(os.Stderr, "Error: requested IV for hop (%d) exceeds array length (%d)\n", intermediateHop, m.intermediateHops)
		os.Exit(1)
	}
	return m.ivs[intermediateHop]
}

func (m *encMessage) getAntiTag() []byte {
	digest, err := blake2s.New256(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating digest: %v\n", err)
		os.Exit(1)
	}
	digest.Write(m.payload[headerBytes:])
	return digest.Sum(nil)
}

func (m *encMessage) encryptBody(key, iv []byte) {
	if !m.gotPayload {
		fmt.Fprintln(os.Stderr, "Error: cannot encrypt payload until it's defined")
		os.Exit(1)
	}
	if len(key) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid key length. Expected=32, Got=%d\n", len(key))
		os.Exit(1)
	}
	if len(iv) != 16 {
		fmt.Fprintf(os.Stderr, "Error: invalid IV length. Expected=16, Got=%d\n", len(iv))
		os.Exit(1)
	}

	copy(
		m.payload[headersBytes:],
		aesCtr(
			m.payload[headersBytes:],
			key,
			iv,
		),
	)
}

func (m *encMessage) encryptAll(hop int) {
	key := m.getKey(hop)
	for slot := 0; slot < maxChainLength; slot++ {
		sbyte := slot * headerBytes
		ebyte := (slot + 1) * headerBytes
		iv := m.getIV(hop, slot)
		copy(
			m.payload[sbyte:ebyte],
			aesCtr(m.payload[sbyte:ebyte], key, iv),
		)
	}
	iv := m.getIV(hop, maxChainLength)
	copy(
		m.payload[headersBytes:],
		aesCtr(m.payload[headersBytes:], key, iv),
	)
}

func (m *encMessage) getIV(intermediateHop, slot int) []byte {
	if m.chainLength == 0 {
		fmt.Fprintln(os.Stderr, "Error: cannot get an IV until the chain length is defined")
		os.Exit(1)
	}
	return seqIV(m.ivs[intermediateHop], slot)
}

func seqIV(partialIV []byte, slot int) []byte {
	if len(partialIV) != 12 {
		fmt.Fprintf(os.Stderr, "Error: invalid iv input: expected 12 bytes, got %d bytes\n", len(partialIV))
		os.Exit(1)
	}
	iv := make([]byte, 16)
	copy(iv[0:4], partialIV[0:4])
	copy(iv[8:16], partialIV[4:12])
	ctr := make([]byte, 4)
	binary.LittleEndian.PutUint32(ctr, uint32(slot))
	copy(iv[4:8], ctr)
	return iv
}

func (m *encMessage) shiftHeaders() {
	bottomHeader := headersBytes - headerBytes
	copy(m.payload[headerBytes:], m.payload[:bottomHeader])
}

func (m *encMessage) insertHeader(header []byte) {
	if len(header) != headerBytes {
		fmt.Fprintf(os.Stderr, "Error: invalid header length. Expected=%d, Got=%d\n", headerBytes, len(header))
		os.Exit(1)
	}
	copy(m.payload[:headerBytes], header)
}

func (m *encMessage) deterministic(hop int) {
	if m.chainLength == 0 {
		fmt.Fprintln(os.Stderr, "Error: cannot generate deterministic headers until chain length has been specified")
		os.Exit(1)
	}
	bottomSlot := maxChainLength - 1
	topSlot := bottomSlot - (m.intermediateHops - hop - 1)
	
	for slot := topSlot; slot <= bottomSlot; slot++ {
		right := bottomSlot - slot + hop
		useSlot := bottomSlot
		fakeHead := make([]byte, headerBytes)
		
		for interHop := right; interHop-hop >= 0; interHop-- {
			key := m.getKey(interHop)
			iv := m.getIV(interHop, useSlot)
			copy(fakeHead, aesCtr(fakeHead, key, iv))
			useSlot--
		}
		
		sByte := slot * headerBytes
		eByte := sByte + headerBytes
		copy(m.payload[sByte:eByte], fakeHead)
	}
}

func encodeMsg(plain []byte, chain []string, final slotFinal) []byte {
	var err error
	var hop string
	m := newEncMessage()
	m.setChainLength(len(chain))
	length := m.setPlainText(plain)
	hop = popstr(&chain)
	final.setBodyBytes(length)
	slotData := newSlotData()
	slotData.setExit()
	slotData.setAesKey(crandom.Randbytes(32))
	slotData.setPacketID(final.getPacketID())
	slotData.setPacketInfo(final.encode())
	
	remailer, err := PubRing.Get(hop)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Remailer unknown in public keyring\n", hop)
		os.Exit(1)
	}
	
	header := newEncodeHeader()
	header.setRecipient(remailer.Keyid, remailer.PK)
	m.encryptBody(slotData.aesKey, final.aesIV)
	m.shiftHeaders()
	if len(chain) > 0 {
		m.deterministic(0)
	}
	slotData.setTagHash(m.getAntiTag())
	slotDataBytes := slotData.encode()
	m.insertHeader(header.encode(slotDataBytes))

	interHops := m.getIntermediateHops()
	for interHop := 0; interHop < interHops; interHop++ {
		inter := newSlotIntermediate()
		inter.setPartialIV(m.getPartialIV(interHop))
		inter.setNextHop(hop)
		hop = popstr(&chain)
		slotData = newSlotData()
		slotData.setAesKey(m.getKey(interHop))
		slotData.setPacketInfo(inter.encode())
		m.encryptAll(interHop)
		m.shiftHeaders()
		m.deterministic(interHop + 1)
		slotData.setTagHash(m.getAntiTag())
		slotDataBytes = slotData.encode()
		header = newEncodeHeader()
		
		remailer, err := PubRing.Get(hop)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Remailer unknown in public keyring\n", hop)
			os.Exit(1)
		}
		
		header.setRecipient(remailer.Keyid, remailer.PK)
		m.insertHeader(header.encode(slotDataBytes))
	}
	
	if len(chain) != 0 {
		fmt.Fprintln(os.Stderr, "Error: after encoding, chain was not empty")
		os.Exit(1)
	}
	return m.getPayload()
}

type slotIntermediate struct {
	gotAesIV12 bool
	aesIV12    []byte
	nextHop    []byte
}

func newSlotIntermediate() *slotIntermediate {
	return &slotIntermediate{
		gotAesIV12: false,
		aesIV12:    make([]byte, 12),
		nextHop:    make([]byte, 52),
	}
}

func (s *slotIntermediate) setPartialIV(partialIV []byte) {
	if len(partialIV) != 12 {
		fmt.Fprintf(os.Stderr, "Error: invalid iv input: expected 12 bytes, got %d bytes\n", len(partialIV))
		os.Exit(1)
	}
	s.gotAesIV12 = true
	copy(s.aesIV12, partialIV)
}

func (s *slotIntermediate) setNextHop(nh string) {
	if len(nh) > 52 {
		fmt.Fprintln(os.Stderr, "Error: next hop address exceeds 52 chars")
		os.Exit(1)
	}
	s.nextHop = []byte(nh + strings.Repeat("\x00", 52-len(nh)))
}

func (s *slotIntermediate) encode() []byte {
	if !s.gotAesIV12 {
		fmt.Fprintln(os.Stderr, "Error: cannot encode until partial IV is defined")
		os.Exit(1)
	}
	buf := new(bytes.Buffer)
	buf.Write(s.aesIV12)
	buf.Write(s.nextHop)
	if buf.Len() != 64 {
		fmt.Fprintf(os.Stderr, "Error: incorrect buffer length: Expected=64, Got=%d\n", buf.Len())
		os.Exit(1)
	}
	return buf.Bytes()
}

func (f *slotFinal) getPacketID() []byte {
	return f.packetID
}

func aesCtr(in, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cipher: %v\n", err)
		os.Exit(1)
	}
	out := make([]byte, len(in))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, in)
	return out
}

func popstr(s *[]string) string {
	slice := *s
	element := slice[len(slice)-1]
	slice = slice[:len(slice)-1]
	*s = slice
	return element
}

func armor(w io.Writer, payload []byte) {
	if len(payload) != messageBytes {
		fmt.Fprintf(os.Stderr, "Error: incorrect payload length. Expected=%d, Got=%d\n", messageBytes, len(payload))
		os.Exit(1)
	}
	
	w.Write([]byte("::\n"))
	w.Write([]byte(fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)))
	w.Write([]byte("-----BEGIN REMAILER MESSAGE-----\n"))
	w.Write([]byte(fmt.Sprintf("%d\n", len(payload))))
	
	digest, err := blake2s.New256(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating digest: %v\n", err)
		os.Exit(1)
	}
	digest.Write(payload)
	w.Write([]byte(hex.EncodeToString(digest.Sum(nil)) + "\n"))
	
	wrap64(w, payload, base64LineWrap)
	w.Write([]byte("\n-----END REMAILER MESSAGE-----\n"))
}

func wrap64(writer io.Writer, b []byte, wrap int) {
	breaker := NewLineBreaker(writer, wrap)
	b64 := base64.NewEncoder(base64.StdEncoding, breaker)
	b64.Write(b)
	b64.Close()
	breaker.Close()
}

type lineBreaker struct {
	lineLength  int
	line        []byte
	used        int
	out         io.Writer
	haveWritten bool
}

func NewLineBreaker(out io.Writer, lineLength int) *lineBreaker {
	return &lineBreaker{
		lineLength: lineLength,
		line:       make([]byte, lineLength),
		used:       0,
		out:        out,
	}
}

func (l *lineBreaker) Write(b []byte) (n int, err error) {
	n = len(b)
	
	if n == 0 {
		return
	}
	
	if l.used == 0 && l.haveWritten {
		_, err = l.out.Write([]byte{'\n'})
		if err != nil {
			return
		}
	}
	
	if l.used+len(b) < l.lineLength {
		l.used += copy(l.line[l.used:], b)
		return
	}
	
	l.haveWritten = true
	_, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := l.lineLength - l.used
	l.used = 0
	
	_, err = l.out.Write(b[0:excess])
	if err != nil {
		return
	}
	
	_, err = l.Write(b[excess:])
	return
}

func (l *lineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
		if err != nil {
			return
		}
	}
	
	return
}
