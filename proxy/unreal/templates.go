package unreal

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lunixbochs/struc"
)

// TArray //

type TArray[T any] struct {
	// Can't get it working as just a []T alias type, struc checks for if it's a slice
	// before checking if it's a `struc.Custom`
	Items []T
}

func (arr *TArray[T]) Unpack(r io.Reader, _ int, opt *struc.Options) error {
	var len int32
	if err := binary.Read(r, opt.Order, &len); err != nil {
		return err
	} else if len < 0 {
		return fmt.Errorf("TArray len underflow")
	}

	arr.Items = make([]T, len)
	for i := 0; i < int(len); i++ {
		if err := struc.UnpackWithOptions(r, &arr.Items[i], opt); err != nil {
			return err
		}
	}

	return nil
}

func (arr *TArray[T]) Pack(p []byte, opt *struc.Options) (int, error) {
	panic("TArray Pack() unimplemented")
}

func (arr *TArray[T]) Size(opt *struc.Options) int {
	total := 4
	for i := range arr.Items {
		if sizer, ok := any(&arr.Items[i]).(interface{ Size(*struc.Options) int }); ok {
			total += sizer.Size(opt)
		} else {
			size, err := struc.Sizeof(&arr.Items[i])
			if err != nil {
				panic(fmt.Errorf("TArray struc.Sizeof: %w", err))
			}
			total += size
		}
	}

	return total
}

func (arr *TArray[T]) String() string {
	return fmt.Sprintf("%v", arr.Items)
}
