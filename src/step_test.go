package step

import (
	"fmt"
	"os"
	"testing"
)

func TestOpen(t *testing.T) {

	// 移除文件
	os.RemoveAll("./testdata/")

	type args struct {
		opt Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful",
			args: args{
				Option{
					Directory:       "./testdata",
					DataFileMaxSize: defaultMaxFileSize,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Open(tt.args.opt); (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type userinfo struct {
	Name string
	Age  uint8
}

func TestPutANDGet(t *testing.T) {
	os.RemoveAll("./testdata/")

	err := Open(Option{
		Directory:       "./testdata",
		DataFileMaxSize: defaultMaxFileSize,
	})

	if err != nil {
		t.Error(err)
	}

	user := userinfo{
		Name: "Leon Ding",
		Age:  22,
	}

	checkErr(t, Put([]byte("foo"), Bson(&user)))

	// time.Sleep(5 * time.Second)
	var u userinfo

	Get([]byte("foo")).Unwrap(&u)

	t.Log(u)
	checkErr(t, Close())
}

func TestSaveData(t *testing.T) {
	t.Log(active)
	err := Open(Option{
		Directory:       "./testdata",
		DataFileMaxSize: defaultMaxFileSize,
	})

	if err != nil {
		t.Error(err)
	}

	for i := 0; i < 100; i++ {
		k := fmt.Sprintf("test_key_%d", i)
		v := fmt.Sprintf("test_value_%d", i)
		err := Put([]byte(k), []byte(v))
		if err != nil {
			t.Error(err)
		}
	}

	err = Close()
	if err != nil {
		t.Error(err)
	}
}

func TestRemove(t *testing.T) {
	os.RemoveAll("./data/")
	err := Open(DefaultOption)
	if err != nil {
		t.Error(err)
	}
	err = Put([]byte("key"), []byte("value"))
	if err != nil {
		return
	}
	Remove([]byte("key"))
	value := index[HashedFunc.Sum64([]byte("key"))]
	t.Log(value)
	checkErr(t, Close())
}
