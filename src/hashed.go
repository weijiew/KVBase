package step

// Hashed 根据输入的字符串生成 64 位无符号整数的哈希值
type Hashed interface {
	Sum64([]byte) uint64
}

// DefaultHashFunc 返回一个新的64位FNV-1a哈希值，不做任何内存分配
// 它的Sum64方法将以big-endian的字节顺序排列数值
func DefaultHashFunc() Hashed {
	return fnv64a{}
}

type fnv64a struct{}

const (
	// offset64 FNVa offset basis.
	// See https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function#FNV-1a_hash
	offset64 = 14695981039346656037
	// prime64 FNVa prime value.
	// See https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function#FNV-1a_hash
	prime64 = 1099511628211
)

// 输入字符串并返回 uint64 哈希值
func (fnv64a) Sum64(key []byte) uint64 {
	var hash uint64 = offset64
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= prime64
	}
	return hash
}
