package step

import (
	"strconv"

	"gopkg.in/mgo.v2/bson"
)

// Log the key value data
type Log struct {
	Key, Value []byte
}

// Item each data operation log item
// | TS 8 | CRC 4 | KS 4 | VS 4  | KEY ? | VALUE ? |
// ItemPadding = 8 + 12 = 20 byte 20 * 8 = 160 bit
type Item struct {
	TimeStamp uint64 // Create timestamp
	CRC32     uint32 // Cyclic check code
	KeySize   uint32 // The size of the key
	ValueSize uint32 // The size of the value
	Log              // Key string, value serialization
}

// NewItem build a data log item
func NewItem(key, value []byte, timestamp uint64) *Item {
	return &Item{
		TimeStamp: timestamp,
		Log: Log{
			Key:   key,
			Value: value,
		},
	}
}

// Data returns to the upper-level data item
type Data struct {
	Err error
	*Item
}

// IsError return an error
func (d Data) IsError() bool {
	return d.Err != nil
}

// Unwrap specifies a type pointer to parse data
func (d *Data) Unwrap(v interface{}) {
	if d.Item != nil {
		_ = bson.Unmarshal(d.Value, v)
	}
}

// String convert data to a string
func (d Data) String() string {
	if d.Item != nil {
		return string(d.Value)
	}
	return ""
}

// Int convert data to a int
func (d Data) Int() int {
	if d.Item != nil {
		num, err := strconv.Atoi(string(d.Value))
		if err != nil {
			return 0
		}
		return num
	}
	return 0
}

// Float convert data to a float64
func (d Data) Float() float64 {
	if d.Item != nil {
		num, err := strconv.ParseFloat(string(d.Value), 64)
		if err != nil {
			return 0.0
		}
		return num
	}
	return 0.0
}

// Bool convert data to a bool
func (d Data) Bool() bool {
	if d.Item != nil {
		b, err := strconv.ParseBool(string(d.Value))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

// Bson convert the data to Bson binary
func Bson(v interface{}) []byte {
	if v == nil {
		// ??? NIL
		return []byte{}
	}
	bytes, _ := bson.Marshal(v)
	return bytes
}
