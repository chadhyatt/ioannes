package unreal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/lunixbochs/struc"
)

// FString //

type FString string

func (s *FString) Unpack(r io.Reader, _ int, opt *struc.Options) error {
	var len int32
	if err := binary.Read(r, opt.Order, &len); err != nil {
		return fmt.Errorf("read len: %w", err)
	}
	if len == 0 {
		return nil
	}

	if len < 0 { // Is a 16-bit wide char string
		len = -len

		buf := make([]byte, len*2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("read buf: %w", err)
		}
		bufU16 := make([]uint16, len)
		if err := binary.Read(bytes.NewReader(buf), opt.Order, &bufU16); err != nil {
			return err
		}

		*s = FString(utf16.Decode(bufU16[:len-2]))
	} else {
		buf := make([]byte, len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("read buf: %w", err)
		}
		*s = FString(buf[:len-1])
	}

	return nil
}

func (s *FString) Pack(p []byte, opt *struc.Options) (int, error) {
	panic("FString Pack() unimplemented")
}

func (s *FString) Size(opt *struc.Options) int {
	return len(*s) + 1
}

func (s *FString) String() string {
	return string(*s)
}

// FGuid //

type FGuid struct {
	A uint32
	B uint32
	C uint32
	D uint32
}

// FName //
type FName struct {
	String FString
	Flags  uint64
}
