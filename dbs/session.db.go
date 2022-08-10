package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type SessionDB struct {
	db *badger.DB
}

func NewSessionDB(db *badger.DB) SessionDB {
	return SessionDB{
		db: db,
	}
}

const MAX_SESSION_TIME time.Duration = 7 * 24 * time.Hour

type SessionEntry struct {
	_        struct{} `cbor:",toarray"`
	Username string
}

func (h *SessionDB) NewSessionEntry(sessionInst SessionEntry) ([]byte, error) {
	sessionBytes, err := cbor.Marshal(sessionInst)
	if err != nil {
		return []byte{}, errors.New("Failed to marshal session. The error is: " + err.Error())
	}

	randomEntryId, _ := uuid.NewRandom()
	sessionEntryId := []byte("session-" + randomEntryId.String())

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(sessionEntryId, sessionBytes).WithTTL(MAX_SESSION_TIME)
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return []byte{}, errors.New("Failed creating session db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return []byte{}, errors.New("Failed saving session entry. The error is: " + err.Error())
	}

	return []byte(randomEntryId.String()), nil
}

func (h *SessionDB) UpdateSessionEntry(entryId []byte, sessionInst SessionEntry) error {
	sessionEntryId := append([]byte("session-"), entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	sessionInstBytes, err := cbor.Marshal(sessionInst)
	if err != nil {
		return errors.New("Failed to marshal session. The error is: " + err.Error())
	}

	err = dbtxn.Set(sessionEntryId, sessionInstBytes)
	if err != nil {
		return errors.New("Failed to create saving inst. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to save session. The error is: " + err.Error())
	}

	return nil
}

func (h *SessionDB) GetSessionEntry(entryId []byte) (*SessionEntry, error) {
	sessionEntryId := append([]byte("session-"), entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(sessionEntryId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The entry with id %s does not exist", hex.EncodeToString(entryId))
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var sessionEntryInst SessionEntry
	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &sessionEntryInst, nil
}
