package step

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"time"
)

// 数据编码器
type Encoder struct {
	Encryptor      // 加密的具体实现
	enable    bool // 是否启用加密解密
}

// 启用 AES 加密
func AES() *Encoder {
	return &Encoder{
		enable:    true,
		Encryptor: new(AESEncryptor),
	}
}

// Write 将 item 写入当前激活文件中
func (e *Encoder) Write(item *Item, file *os.File) (int, error) {
	// 是否开启加密
	if e.enable && e.Encryptor != nil {
		// building source data
		sd := &SourceData{
			Secret: Secret,
			Data:   item.Value,
		}
		if err := e.Encode(sd); err != nil {
			return 0, errors.New("an error occurred in the encryption encoder")
		}
		item.Value = sd.Data
		return bufToFile(binaryEncode(item), file)
	}

	return bufToFile(binaryEncode(item), file)
}

func (e *Encoder) Read(rec *record) (*Item, error) {
	// Parse to data entities
	item, err := parseLog(rec)

	if err != nil {
		return nil, err
	}

	if e.enable && e.Encryptor != nil && item != nil {
		// Decryption operation
		sd := &SourceData{
			Secret: Secret,
			Data:   item.Value,
		}
		if err := e.Decode(sd); err != nil {
			return nil, errors.New("a data decryption error occurred")
		}
		item.Value = sd.Data
		return item, nil
	}

	return item, nil
}

// WriteIndex 文件的索引项
func (Encoder) WriteIndex(item indexItem, file *os.File) (int, error) {
	// | CRC32 4 | IDX 8 | FID 8  | TS 4 | ET 4 | SZ 4 | OF 4 |
	buf := make([]byte, 36)

	binary.LittleEndian.PutUint64(buf[4:12], item.idx)
	binary.LittleEndian.PutUint64(buf[12:20], uint64(item.FID))
	binary.LittleEndian.PutUint32(buf[20:24], item.Timestamp)
	binary.LittleEndian.PutUint32(buf[24:28], item.ExpireTime)
	binary.LittleEndian.PutUint32(buf[28:32], item.Size)
	binary.LittleEndian.PutUint32(buf[32:36], item.Offset)

	binary.LittleEndian.PutUint32(buf[:4], crc32.ChecksumIEEE(buf[4:]))

	return file.Write(buf)
}

// ReadIndex 读取文件的索引
func (Encoder) ReadIndex(buf []byte) error {
	var (
		item indexItem
	)

	if binary.LittleEndian.Uint32(buf[:4]) != crc32.ChecksumIEEE(buf[4:]) {
		return errors.New("index record verification failed")
	}

	item.record = new(record)

	item.idx = binary.LittleEndian.Uint64(buf[4:12])
	item.FID = int64(binary.LittleEndian.Uint64(buf[12:20]))
	item.Timestamp = binary.LittleEndian.Uint32(buf[20:24])
	item.ExpireTime = binary.LittleEndian.Uint32(buf[24:28])
	item.Size = binary.LittleEndian.Uint32(buf[28:32])
	item.Offset = binary.LittleEndian.Uint32(buf[32:36])

	// Determine expiration date
	if uint32(time.Now().Unix()) <= item.ExpireTime {
		index[item.idx] = &record{
			FID:        item.FID,
			Size:       item.Size,
			Offset:     item.Offset,
			Timestamp:  item.Timestamp,
			ExpireTime: item.ExpireTime,
		}
	}

	return nil
}

// parseLog 从 item 中解析数据
func parseLog(rec *record) (*Item, error) {
	// 通过 record 找到该文件的标识符
	if file, ok := fileList[rec.FID]; ok {
		// 根据文件尺寸申请相应的空间
		data := make([]byte, rec.Size)
		// 将内读取到 data 中
		_, err := file.ReadAt(data, int64(rec.Offset))
		if err != nil {
			return nil, err
		}
		return binaryDecode(data), nil
	}
	return nil, errors.New("no readable data file found")
}

// binaryDecode 将二进制数据解析为 item
func binaryDecode(data []byte) *Item {
	// 检查数据是否完整
	if binary.LittleEndian.Uint32(data[:4]) != crc32.ChecksumIEEE(data[4:]) {
		return nil
	}

	var item Item
	// | CRC 4 | TS 8  | KS 4 | VS 4  | KEY ? | VALUE ? |
	item.CRC32 = binary.LittleEndian.Uint32(data[:4])
	item.TimeStamp = binary.LittleEndian.Uint64(data[4:12])
	item.KeySize = binary.LittleEndian.Uint32(data[12:16])
	item.ValueSize = binary.LittleEndian.Uint32(data[16:20])

	// 解析 log 数据
	item.Key, item.Value = make([]byte, item.KeySize), make([]byte, item.ValueSize)
	copy(item.Key, data[itemPadding:itemPadding+item.KeySize])
	copy(item.Value, data[itemPadding+item.KeySize:itemPadding+item.KeySize+item.ValueSize])
	return &item
}

// binaryEncode 将数据 item 解析为二进制切片
func binaryEncode(item *Item) []byte {
	// fix bug: https://github.com/golang/go/issues/24402
	item.KeySize = uint32(len(item.Key))
	item.ValueSize = uint32(len(item.Value))

	buf := make([]byte, itemPadding+item.KeySize+item.ValueSize)

	// | CRC 4 | TS 8  | KS 4 | VS 4  | KEY ? | VALUE ? |
	// ItemPadding = 8 + 12 = 20 bit
	binary.LittleEndian.PutUint64(buf[4:12], item.TimeStamp)
	binary.LittleEndian.PutUint32(buf[12:16], item.KeySize)
	binary.LittleEndian.PutUint32(buf[16:20], item.ValueSize)

	//buf = append(buf, item.Key...)
	//buf = append(buf, item.Value...)

	// add key data to the buffer
	copy(buf[itemPadding:itemPadding+item.KeySize], item.Key)
	// add value data to the buffer
	copy(buf[itemPadding+item.KeySize:itemPadding+item.KeySize+item.ValueSize], item.Value)

	// add crc32 code to the buffer
	binary.LittleEndian.PutUint32(buf[:4], crc32.ChecksumIEEE(buf[4:]))

	return buf
}

// bufToFile entity 从缓冲池中写入文件
func bufToFile(data []byte, file *os.File) (int, error) {
	if n, err := file.Write(data); err == nil {
		return n, nil
	}
	return 0, errors.New("error writing encode buffer data to log")
}
