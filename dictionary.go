// Package edgedict interacts with MS Edge dictionaries.
package edgedict

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/ioutil"
	"github.com/ncruces/go-sqlite3/vfs/readervfs"
)

var (
	dbID       atomic.Uint64
	dbIDPrefix string
)

// Dictionary provides read access to the contents of a MS Edge dictionary.
type Dictionary struct {
	id string
	db *sqlite3.Conn
	df *os.File
}

// Ref points to a definition.
type Ref struct {
	shard int
	index int
}

func (r Ref) String() string {
	return strconv.Itoa(r.shard) + "/" + strconv.Itoa(r.index)
}

func init() {
	ss := sha1.Sum([]byte(reflect.TypeOf(&Dictionary{}).PkgPath()))
	dbIDPrefix = hex.EncodeToString(ss[:])
}

// New opens a MS Edge dictionary from a ReaderAt supporting seeking.
func New(r io.ReaderAt) (*Dictionary, error) {
	id := dbIDPrefix + "." + strconv.FormatUint(dbID.Add(1), 10) + ".db"
	readervfs.Create(id, ioutil.NewSizeReaderAt(r))

	db, err := sqlite3.Open("file:" + id + "?vfs=reader")
	if err != nil {
		readervfs.Delete(id)
		return nil, err
	}

	return &Dictionary{
		id: id,
		db: db,
	}, nil
}

// Open opens a MS Edge dictionary from a path.
func Open(name string) (*Dictionary, error) {
	df, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	d, err := New(df)
	if err != nil {
		df.Close()
		return nil, err
	}
	d.df = df

	return d, nil
}

// Close cleans up any open resources.
func (d *Dictionary) Close() error {
	readervfs.Delete(d.id)
	if d.df != nil {
		d.df.Close()
	}
	return d.db.Close()
}

// Lookup finds a word in the dictionary and returns the definition(s). If the
// word does not exist, a nil slice will be returned.
func (d *Dictionary) Lookup(word string) ([]Entry, error) {
	rs, err := d.LookupRef(word)
	if err != nil {
		return nil, err
	}

	if rs == nil {
		return nil, nil
	}

	es := make([]Entry, len(rs))
	for i, r := range rs {
		seg, err := d.Get(r)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(seg, &es[i]); err != nil {
			return nil, err
		}
	}
	return es, nil
}

// LookupRef finds an entry in the dictionary. If the word does not exist, a nil
// err and slice will be returned.
func (d *Dictionary) LookupRef(word string) ([]Ref, error) {
	stmt, _, err := d.db.Prepare("SELECT JsonShardID, JsonIndex FROM WordLookup WHERE Name = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var rs []Ref
	if err := stmt.BindText(1, word); err != nil {
		return nil, err
	}
	for stmt.Step() {
		rs = append(rs, Ref{
			shard: stmt.ColumnInt(0),
			index: stmt.ColumnInt(1),
		})
	}
	return rs, stmt.Err()
}

// Get gets the raw entry referenced by r.
func (d *Dictionary) Get(r Ref) ([]byte, error) {
	buf, err := d.readShard(r.shard)
	if err != nil {
		return nil, err
	}

	seg, err := d.indexShard(buf, r.index)
	if err != nil {
		return nil, err
	}
	return seg, nil
}

// Words gets all words from the dictionary.
func (d *Dictionary) Words() ([]string, error) {
	stmt, _, err := d.db.Prepare("SELECT Name FROM WordLookup")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var ws []string
	for stmt.Step() {
		ws = append(ws, stmt.ColumnText(0))
	}
	return ws, stmt.Err()
}

// Entries gets references to all unique definitions from the dictionary.
func (d *Dictionary) Entries() ([]Ref, error) {
	stmt, _, err := d.db.Prepare("SELECT DISTINCT JsonShardID, JsonIndex FROM WordLookup")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var rs []Ref
	for stmt.Step() {
		rs = append(rs, Ref{
			shard: stmt.ColumnInt(0),
			index: stmt.ColumnInt(1),
		})
	}
	return rs, stmt.Err()
}

// WalkRefs efficiently iterates over all word references from the dictionary,
// breaking if fn returns a non-nil error.
func (d *Dictionary) WalkRefs(fn func(term string, ref Ref) error) error {
	stmt, _, err := d.db.Prepare("SELECT Name, JsonShardID, JsonIndex FROM WordLookup")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for stmt.Step() {
		if err := fn(stmt.ColumnText(0), Ref{
			shard: stmt.ColumnInt(1),
			index: stmt.ColumnInt(2),
		}); err != nil {
			return err
		}
	}
	return stmt.Err()
}

// Walk efficiently iterates over all unique definitions from the dictionary,
// breaking if fn returns a non-nil error.
func (d *Dictionary) Walk(fn func(ref Ref, buf []byte) error) error {
	stmt, _, err := d.db.Prepare("SELECT rowid, ID FROM Shard")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for stmt.Step() {
		rowid := stmt.ColumnInt64(0)
		shard := stmt.ColumnInt(1)

		buf, err := d.readShardBlob(rowid)
		if err != nil {
			return err
		}
		if err := d.walkShard(buf, func(idx int, data []byte) error {
			return fn(Ref{
				shard: shard,
				index: idx,
			}, data)
		}); err != nil {
			return err
		}
	}
	if err := stmt.Err(); err != nil {
		return err
	}
	return nil
}

func (d *Dictionary) readShard(shard int) ([]byte, error) {
	stmt, _, err := d.db.Prepare("SELECT rowid FROM Shard WHERE ID == ? LIMIT 1")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	if err := stmt.BindInt(1, shard); err != nil {
		return nil, err
	}
	if stmt.Step() {
		return d.readShardBlob(stmt.ColumnInt64(0))
	}
	if err := stmt.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("shard not found")
}

func (d *Dictionary) readShardBlob(rowid int64) ([]byte, error) {
	blob, err := d.db.OpenBlob("main", "Shard", "ShardData", rowid, false)
	if err != nil {
		return nil, err
	}
	defer blob.Close()

	zr, err := gzip.NewReader(blob)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return io.ReadAll(zr)
}

func (d *Dictionary) indexShard(shard []byte, idx int) ([]byte, error) {
	var data []byte
	if err := d.walkShard(shard, func(i int, d []byte) error {
		if idx == i {
			data = d
			return io.EOF
		}
		return nil
	}); err != nil && err != io.EOF {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("segment not found")
	}
	return data, nil
}

func (d *Dictionary) walkShard(shard []byte, fn func(idx int, data []byte) error) error {
	hdr := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00}
	if !bytes.HasPrefix(shard, hdr) {
		return errors.New("unexpected shard header")
	}

	// first segment starts at index 2
	if i := bytes.Index(shard, []byte{'\x06', '\x02', '\x00', '\x00', '\x00'}); i == -1 {
		return errors.New("failed to find first segment in shard")
	} else {
		shard = shard[i:]
	}

	for {
		if len(shard) == 0 {
			return errors.New("unexpected eof when reading shard segment")
		}
		if shard[0] == '\x0B' {
			if len(shard) != 1 {
				return errors.New("unexpected junk after last shard segment")
			}
			break
		}
		if shard[0] != '\x06' {
			return errors.New("unexpected byte at start of shard segment")
		}
		shard = shard[1:]

		var idx int
		if len(shard) < 4 {
			return errors.New("unexpected eof while reading segment index")
		} else {
			idx = int(leUint32(shard[:4]))
			shard = shard[4:]
		}
		if idx < 2 {
			return errors.New("segment index out of range")
		} else {
			idx -= 2
		}

		var sz int
		// how I figured this out:
		// - if you look closely, you'll notice that the last byte before the JSON never has the high bit set
		// - then, you notice that there's a size threshold at which there is an additional byte in the header
		// - which leads you to realize that it's simply the size encoded as a dynamic-length integer (high bit set except for the last byte)
		// - and then you notice that the size threshold from 2 bytes to 3 is 16383 (= 0x3FFF = 0b0011111111111111)
		// - which implies that it's parsed as an unsigned integer since all bits but the first are used
		if v, n := leUvarint(shard); n == 0 {
			return errors.New("unexpected eof while reading segment data size")
		} else if n < 0 {
			return errors.New("segment data size overflow")
		} else {
			sz = int(v)
			shard = shard[n:]
		}

		if len(shard) < sz {
			return errors.New("unexpected eof while reading segment data")
		} else {
			if err := fn(idx, shard[:sz:sz]); err != nil {
				return err
			}
			shard = shard[sz:]
		}
	}
	return nil
}

// leUvarint decodes a little-endian variable-length unsigned integer from b,
// returning the value and the number of bytes read. If n is zero, b ended
// unexpectedly. If n is negative, the value overflows a uint64.
func leUvarint(b []byte) (v uint64, n int) {
	var t uint // bits
	for i, x := range b {
		// if we have any set bits after shifting right the remaining bits,
		// we're going to overflow n
		if x>>(64-t) != 0 {
			return v, -(i + 1)
		}

		// add the next byte
		v |= uint64(x&^(1<<7)) << t
		t += 7

		// check if it's the last byte
		if x>>7 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// leUint32 decodes a 4-byte unsigned integer from b.
func leUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}
