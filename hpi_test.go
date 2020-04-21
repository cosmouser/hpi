package hpi

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"
)

func TestScanHeader(t *testing.T) {
	var header Header
	file, err := os.Open("TADEMO.ufo")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()
	err = binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		t.Error(err)
	}
	if header.Marker != HPIMagic {
		t.Errorf("Got %x, wanted %x", header.Marker, HPIMagic)
	}
}
func TestXORDecrypt(t *testing.T) {
	var headerKey uint32 = 0x0000007D
	var expected uint32 = 0xFFFFFE0A
	if value := ^((headerKey * 4) | (headerKey >> 6)); value != expected {
		t.Errorf("Got %x, wanted %x", value, expected)
	}
}
func TestReadAndDecrypt(t *testing.T) {
	var header Header
	file, err := os.Open("Example.ufo")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()
	err = binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		t.Error(err)
	}
	buffSize := header.DirectorySize - header.Start
	key := header.GetKey()
	_, err = ReadAndDecrypt(file, key, int(buffSize), int(header.Start))
	if err != nil {
		t.Error(err)
	}
}
func TestTraverse(t *testing.T) {
	var header Header
	file, err := os.Open("Example.ufo")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()
	err = binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		t.Error(err)
	}
	buffSize := header.DirectorySize - header.Start
	key := header.GetKey()
	buf, err := ReadAndDecrypt(file, key, int(buffSize), int(header.Start))
	if err != nil {
		t.Error(err)
	}
	buf = append(make([]byte, int(header.Start)), buf...)
	dirRead := bytes.NewReader(buf)
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatal(err)
	}
	err = TraverseTree(file, dirRead, key, dir, int(header.Start))
	if err != nil {
		t.Error(err)
	}
	os.RemoveAll(dir)
}
