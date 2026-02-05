package unreal

// Enums

type EHandshakeStatus byte

const (
	HS_NotStarted EHandshakeStatus = iota
	HS_SentChallenge
	HS_Complete
)

type EChannelType byte

const (
	CHTYPE_None    EChannelType = 0
	CHTYPE_Control EChannelType = 1
	CHTYPE_Actor   EChannelType = 2
	CHTYPE_File    EChannelType = 3
	CHTYPE_Voice   EChannelType = 4
	CHTYPE_MAX     EChannelType = 8
)
