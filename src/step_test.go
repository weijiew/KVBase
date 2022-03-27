package step

import (
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
