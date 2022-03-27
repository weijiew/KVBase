package step

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (

	// Secret 加密密钥
	Secret = []byte("ME:QQ:2420498526")

	// 数据根目录
	Root = ""

	// 文件最大尺寸
	// 2 << 8 = 512 << 20 = 536870912 kb
	defaultMaxFileSize int64 = 2 << 8 << 20

	// 全局数据编码器
	encoder *Encoder

	// 数据所在的文件夹
	dataDirectory string

	// 索引所在的文件夹
	indexDirectory string

	// 默认的 hash 函数
	HashedFunc Hashed

	// 全局索引 [uint64 -> record]
	index map[uint64]*record

	// 旧数据的文件描述符
	fileList map[int64]*os.File

	// Data recovery triggers the merge threshold
	// 数据
	totalDataSize int64 = 2 << 8 << 20 << 1 // 1GB

	// 数据文件的扩展名
	dataFileSuffix = ".data"

	// 索引文件的扩展名
	indexFileSuffix = ".index"

	// 当前数据文件的版本
	dataFileVersion int64 = 0

	// Perm 默认文件权限
	Perm = os.FileMode(0750)

	// FRW 在只写模式下打开一个文件
	FRW = os.O_RDWR | os.O_APPEND | os.O_CREATE

	// FR 只读模式下打开文件
	FR = os.O_RDONLY

	// 读写互斥锁，只允许一个写，但是允许多个读
	mutex sync.RWMutex

	// 写入文件的偏移值
	writeOffset uint32 = 0

	// 当前可写的文件
	active *os.File

	// itemPadding 二进制编码头的填充
	itemPadding uint32 = 20
)

var (
	// 按照指定模式打开数据文件
	openDataFile = func(flag int, dataFileIdentifier int64) (*os.File, error) {
		return os.OpenFile(dataSuffixFunc(dataFileIdentifier), flag, Perm)
	}

	// 构建指定的数据文件扩展名 [文件夹 + 版本.data]
	dataSuffixFunc = func(dataFileIdentifier int64) string {
		return fmt.Sprintf("%s%d%s", dataDirectory, dataFileIdentifier, dataFileSuffix)
	}

	// 按照指定模式打开索引文件
	openIndexFile = func(flag int, dataFileIdentifier int64) (*os.File, error) {
		return os.OpenFile(indexSuffixFunc(dataFileIdentifier), flag, Perm)
	}

	// 构建指定的索引文件扩展名 [文件夹 + 版本.index]
	indexSuffixFunc = func(dataFileIdentifier int64) string {
		return fmt.Sprintf("%s%d%s", indexDirectory, dataFileIdentifier, indexFileSuffix)
	}
)

// record Mapping Data Record
type record struct {
	FID        int64  // data file id
	Size       uint32 // data record size
	Offset     uint32 // data record offset
	Timestamp  uint32 // data record create timestamp
	ExpireTime uint32 // data record expire time
}

// 打开
func Open(opt Option) error {
	// 做一些初始化的工作
	// 例如数据加密加密方式
	opt.Validation()

	// 初始化引擎的组件
	initialize()

	if ok, err := pathExists(Root); ok {
		// 启动恢复数据
		return recoverData()
	} else if err != nil {
		// 路径是非法的
		panic("The current path is invalid!!!")
	}

	// 如果数据文件夹不存在就创建
	if err := os.MkdirAll(dataDirectory, Perm); err != nil {
		panic("Failed to create a working directory!!!")
	}

	// 如果索引文件夹不存在就创建
	if err := os.MkdirAll(indexDirectory, Perm); err != nil {
		panic("Failed to create a working directory!!!")
	}

	// 文件夹创建好，写入数据
	return createActiveFile()
}

// 创建一个新的文件
func createActiveFile() error {
	mutex.Lock()
	defer mutex.Unlock()

	// 初始化可写文件的偏移值和文件标识符
	writeOffset = 0
	dataFileVersion++

	// 打开数据文件
	if file, err := openDataFile(FRW, dataFileVersion); err == nil {
		active = file
		fileList[dataFileVersion] = active
		return nil
	}

	return errors.New("failed to create writable data file")
}

// 数据恢复
func recoverData() error {

	// 判断文件是否超过上限(1G)
	if dataTotalSize() >= totalDataSize {
		// TODO 合并数据
		if err := migrate(); err != nil {
			return err
		}
	}

	// 找到最后一个数据文件，判断是否已满
	if file, err := findLatestDataFile(); err == nil {
		info, _ := file.Stat()
		if info.Size() >= defaultMaxFileSize {
			if err := createActiveFile(); err != nil {
				return err
			}
			// 当数据已满时，将创建一个新的可写文件并建立一个索引
			return buildIndex()
		}
		// 如果数据文件上次没有被填满
		// 就会被设置为可写，并计算出可写的偏移量
		active = file
		if offset, err := file.Seek(0, os.SEEK_END); err == nil {
			writeOffset = uint32(offset)
		}
		return buildIndex()
	}

	return errors.New("failed to restore data")
}

// 从数据文件中找到最新的数据文件
func findLatestDataFile() (*os.File, error) {
	version()
	return openDataFile(FRW, dataFileVersion)
}

// 合并脏数据
func migrate() error {
	// 加载索引和数据
	if err := buildIndex(); err != nil {
		return err
	}

	// 获取最近的数据版本
	version()

	var (
		offset       uint32
		file         *os.File
		fileInfo     os.FileInfo
		excludeFiles []int64
		activeItem   = make(map[uint64]*Item, len(index))
	)

	dataFileVersion++

	// 创建用于迁移的目标数据文件
	file, _ = openDataFile(FRW, dataFileVersion)
	excludeFiles = append(excludeFiles, dataFileVersion)
	// 获取 migration 文件的状态
	fileInfo, _ = file.Stat()

	// 迁移活跃的可激活数据
	for idx, rec := range index {
		item, err := encoder.Read(rec)
		if err != nil {
			return err
		}

		activeItem[idx] = item
	}

	for idx, item := range activeItem {
		// Check whether the migration file threshold is reached at each turn
		if fileInfo.Size() >= defaultMaxFileSize {
			// Close and set too read-only to put into map
			if err := file.Sync(); err != nil {
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}

			// The update operation
			dataFileVersion++
			excludeFiles = append(excludeFiles, dataFileVersion)

			file, _ = openDataFile(FRW, dataFileVersion)
			fileInfo, _ = file.Stat()
			offset = 0
		}

		// Write the original content to the new file
		size, err := encoder.Write(item, file)

		if err != nil {
			return err
		}

		// Update the new file ID and offset
		index[idx].FID = dataFileVersion
		index[idx].Size = uint32(size)
		index[idx].Offset = offset

		offset += uint32(size)
	}

	// 清除已删除的数据
	fileInfos, err := ioutil.ReadDir(dataDirectory)

	if err != nil {
		return err
	}

	// 过滤掉已经迁移的数据文件
	for _, info := range fileInfos {
		fileName := fmt.Sprintf("%s%s", dataDirectory, info.Name())
		for _, excludeFile := range excludeFiles {
			if fileName != dataSuffixFunc(excludeFile) {
				if err := os.Remove(fileName); err != nil {
					return err
				}
			}
		}
	}

	// 迁移后，保存最新的索引文件
	return saveIndexToFile()
}

// Memory index file item encoding used
// The size of 288 - bit
type indexItem struct {
	idx uint64
	*record
}

// 将索引文件保存到数据目录中
func saveIndexToFile() (err error) {
	var file *os.File
	defer func() {
		if err := file.Sync(); err != nil {
			return
		}
		if err := file.Close(); err != nil {
			return
		}
	}()

	var channel = make(chan indexItem, 1024)

	go func() {
		for sum64, record := range index {
			channel <- indexItem{
				idx:    sum64,
				record: record,
			}
		}
		close(channel)
	}()

	if file, err = openIndexFile(FRW, time.Now().Unix()); err != nil {
		return
	}

	for v := range channel {
		if _, err = encoder.WriteIndex(v, file); err != nil {
			return
		}
	}

	return
}

// 加载数据文件的版本号
func version() {
	files, _ := ioutil.ReadDir(dataDirectory)
	var datafiles []fs.FileInfo

	// 将 .data 结尾的文件加入 datafiles 中
	for _, file := range files {
		if path.Ext(file.Name()) == dataFileSuffix {
			datafiles = append(datafiles, file)
		}
	}

	var ids []int

	for _, info := range datafiles {
		id := strings.Split(info.Name(), ".")[0]
		i, _ := strconv.Atoi(id)
		ids = append(ids, i)
	}

	sort.Ints(ids)

	// 重置文件计数器和可写文件偏移值
	dataFileVersion = int64(ids[len(ids)-1])
}

func buildIndex() error {

	if err := readIndexItem(); err != nil {
		return err
	}

	// 从索引中找到数据并读取文件描述符
	for _, record := range index {
		// https://stackoverflow.com/questions/37804804/too-many-open-file-error-in-golang
		if fileList[record.FID] == nil {
			file, err := openDataFile(FR, record.FID)
			if err != nil {
				return err
			}
			// Open the original data file
			fileList[record.FID] = file
		}
	}

	return nil

}

// Read index file contents into memory index
func readIndexItem() error {
	if file, err := findLatestIndexFile(); err == nil {
		defer func() {
			if err := file.Sync(); err != nil {
				return
			}
			if err := file.Close(); err != nil {
				return
			}
		}()

		buf := make([]byte, 36)

		for {
			_, err := file.Read(buf)

			if err != nil && err != io.EOF {
				return err
			}

			if err == io.EOF {
				break
			}

			if err = encoder.ReadIndex(buf); err != nil {
				return err
			}
		}

		return nil
	}

	return errors.New("index reading failed")
}

// 在索引文件夹中找到最新的数据文件
func findLatestIndexFile() (*os.File, error) {
	files, err := ioutil.ReadDir(indexDirectory)

	if err != nil {
		return nil, err
	}

	var indexes []fs.FileInfo

	for _, file := range files {
		if path.Ext(file.Name()) == indexFileSuffix {
			indexes = append(indexes, file)
		}
	}

	var ids []int

	for _, info := range indexes {
		id := strings.Split(info.Name(), ".")[0]
		i, err := strconv.Atoi(id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, i)
	}

	sort.Ints(ids)

	return openIndexFile(FR, int64(ids[len(ids)-1]))
}

// 计算文件夹中数据文件的大小
func dataTotalSize() int64 {

	// 读取文件夹内的数据
	files, _ := ioutil.ReadDir(dataDirectory)

	var datafiles []fs.FileInfo

	// 遍历文件
	for _, file := range files {
		// 判断扩展名是否是 .data
		if path.Ext(file.Name()) == dataFileSuffix {
			datafiles = append(datafiles, file)
		}
	}

	var totalSize int64

	for _, datafile := range datafiles {
		totalSize += datafile.Size()
	}

	return totalSize
}

// 初始化引擎的组件
func initialize() {

	// 初始化默认的哈希函数
	if HashedFunc == nil {
		HashedFunc = DefaultHashFunc()
	}

	// 初始化编码器
	if encoder == nil {
		encoder = DefaultEncoder()
	}

	// 初始化索引
	if index == nil {
		index = make(map[uint64]*record)
	}

	// 默认情况下挂载 5 个文件描述符
	fileList = make(map[int64]*os.File, 5)
}

// DefaultEncoder 关闭 AES 加密方式
func DefaultEncoder() *Encoder {
	return &Encoder{
		enable:    false,
		Encryptor: nil,
	}
}
