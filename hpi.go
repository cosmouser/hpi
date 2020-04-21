package hpi

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
)

const (
	// HPIMagic is the first four bytes of the file.
	HPIMagic = 0x49504148

	// SavedGame is BANK in ASCII when the file is a saved game.
	SavedGame = 0x4B4E4142

	// ChunkStart is SQSH in ASCII. It always begins the chunk header.
	ChunkStart = 0x48535153
)

// Header is the only unencrypted part of the file.
type Header struct {
	Marker        uint32
	Save          uint32
	DirectorySize uint32 // This includes the size of the header.
	Key           uint32 // The decryption key.
	Start         uint32
}

// Entry is an entry in the directory.
type Entry struct {
	NameOffset    uint32
	DirDataOffset uint32
	Flag          byte
}

// FileData is what is at an Entry's DirDataOffset when the Flag is 0.
type FileData struct {
	DataOffset uint32
	FileSize   uint32
	Flag       byte // 0: No Compression, 1: LZ77, 2: ZLib
}

// ChunkHeader provides instructions for loading the chunk.
type ChunkHeader struct {
	Marker            uint32
	_                 byte
	CompressionMethod byte
	Encrypted         byte
	CompressedSize    uint32
	DecompressedSize  uint32
	Checksum          uint32
}

// Chunk is the standard block of data in the archive.
type Chunk struct {
	ChunkHeader
	Data []byte
}

// ReadAndDecrypt reads and decrypts buffSize bytes from the HPI file.
func ReadAndDecrypt(reader io.ReadSeeker, key byte, size, offset int) ([]byte, error) {
	seed, err := reader.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if _, err := reader.Read(buf); err != nil {
		return nil, err
	}
	if key == 0 {
		return buf, nil
	}
	for i := range buf {
		tkey := byte(int(seed)+(i)) ^ key
		buf[i] = tkey ^ buf[i]
	}
	return buf, nil
}

// CalculateKey calculates the decryption key from the header's Key field.
func (h Header) GetKey() byte {
	return byte((h.Key << 2) | (h.Key >> 6))
}

// TraverseTree traverses the HPI directory tree.
func TraverseTree(archive, dir io.ReadSeeker, key byte, parent string, offset int) error {
	var (
		numEntries  uint32
		entryOffset uint32
	)
	if _, err := dir.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(dir, binary.LittleEndian, &numEntries); err != nil {
		return err
	}
	if err := binary.Read(dir, binary.LittleEndian, &entryOffset); err != nil {
		return err
	}
	for i := 0; i < int(numEntries); i++ {
		if _, err := dir.Seek(int64(entryOffset)+int64(i*9), io.SeekStart); err != nil {
			return err
		}
		var entry Entry
		if err := binary.Read(dir, binary.LittleEndian, &entry); err != nil {
			return err
		}
		if _, err := dir.Seek(int64(entry.NameOffset), io.SeekStart); err != nil {
			return err
		}
		nameReader := bufio.NewReader(dir)
		fileName, err := nameReader.ReadBytes(0)
		if err != nil {
			return err
		}
		name := path.Join(parent, string(fileName[:len(fileName)-1]))
		if entry.Flag == 1 {
			if err := TraverseTree(archive, dir, key, name, int(entry.DirDataOffset)); err != nil {
				return err
			}
		} else {
			if _, err := os.Stat(parent); os.IsNotExist(err) {
				err = os.MkdirAll(parent, 0744)
				if err != nil {
					return err
				}
			}
			if err := ProcessFile(archive, dir, key, name, int(entry.DirDataOffset)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ProcessFile decrypts and decompresses a file in the archive.
func ProcessFile(archive, dir io.ReadSeeker, key byte, name string, offset int) error {
	var (
		header    FileData
		chunk     Chunk
		numChunks int
		sizes     []uint32
		chunkSum  int
		out       *os.File
	)
	const (
		longLength   = 4
		maxChunkSize = 65536
	)
	out, err := os.Create(name)
	if err != nil {
		return err
	}
	if _, err := dir.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(dir, binary.LittleEndian, &header); err != nil {
		return err
	}
	numChunks = int(header.FileSize) / maxChunkSize
	if int(header.FileSize)%maxChunkSize != 0 {
		numChunks++
	}
	sizes = make([]uint32, numChunks)
	if _, err := archive.Seek(int64(header.DataOffset), io.SeekStart); err != nil {
		return err
	}
	fileData, err := ReadAndDecrypt(archive, key, longLength*numChunks, int(header.DataOffset))
	fileReader := bytes.NewReader(fileData)
	for i := range sizes {
		var chunkSize uint32
		if err := binary.Read(fileReader, binary.LittleEndian, &chunkSize); err != nil {
			return err
		}
		sizes[i] = chunkSize
		chunkSum += int(chunkSize)
	}
	fileData, err = ReadAndDecrypt(archive, key, chunkSum, int(header.DataOffset)+longLength*numChunks)
	if err != nil {
		return err
	}
	fileReader = bytes.NewReader(fileData)
	for range sizes {
		if err := binary.Read(fileReader, binary.LittleEndian, &chunk.ChunkHeader); err != nil {
			return err
		}
		chunk.Data = make([]byte, int(chunk.ChunkHeader.CompressedSize))
		n, err := fileReader.Read(chunk.Data)
		if err != nil {
			return err
		}
		if n != len(chunk.Data) {
			return fmt.Errorf("short read")
		}
		if chunk.ChunkHeader.Encrypted != 0 {
			chunk.Decrypt()
		}
		switch chunk.CompressionMethod {
		case 0:
			io.Copy(out, bytes.NewReader(chunk.Data))
		case 1:
			chunk.Data = Decompress(chunk.Data)
			io.Copy(out, bytes.NewReader(chunk.Data))
		case 2:
			zbuf, err := zlib.NewReader(bytes.NewReader(chunk.Data))
			if err != nil {
				return err
			}
			io.Copy(out, zbuf)
		default:
			return fmt.Errorf("unknown compression method: %x", chunk.CompressionMethod)
		}
	}
	out.Close()
	return nil
}
func (c *Chunk) Decrypt() {
	for i := range c.Data {
		c.Data[i] = (c.Data[i] - byte(i)) ^ byte(i)
	}
}
func Decompress(input []byte) []byte {
	var (
		window       [4096]byte
		windowPos    = 1
		writeBuf     bytes.Buffer
		decompressed []byte
	)
	reader := bytes.NewReader(input)
	for {
		tag, err := reader.ReadByte()
		if err != nil {
			return nil
		}
		for i := 0; i < 8; i++ {
			if (tag & 1) == 0 {
				value, err := reader.ReadByte()
				if err != nil {
					return nil
				}
				err = writeBuf.WriteByte(value)
				if err != nil {
					return nil
				}
				window[windowPos] = value
				windowPos = (windowPos + 1) & 0x0fff
			} else {
				var packedData uint16
				err = binary.Read(reader, binary.LittleEndian, &packedData)
				if err != nil {
					return nil
				}
				windowReadPos := packedData >> 4
				if windowReadPos == 0 {
					decompressed = writeBuf.Bytes()
					return decompressed
				}
				count := (packedData & 0x0f) + 2
				for x := 0; x < int(count); x++ {
					err = writeBuf.WriteByte(window[windowReadPos])
					if err != nil {
						return nil
					}
					window[windowPos] = window[windowReadPos]
					windowReadPos = (windowReadPos + 1) & 0x0fff
					windowPos = (windowPos + 1) & 0x0fff
				}
			}
			tag = tag >> 1
		}
	}
}
