local MAX_PACKETID = 16384
local MAX_CHANNELS = 2048
local MAX_CHSEQUENCE = 1024

local CHTYPE_None = 0
local CHTYPE_MAX = 8

local function makeRelative(val, ref, max)
    --[[
    inline INT BestSignedDifference( INT Value, INT Reference, INT Max )
    {
        return ((Value-Reference+Max/2) & (Max-1)) - Max/2;
    }
    inline INT MakeRelative( INT Value, INT Reference, INT Max )
    {
        return Reference + BestSignedDifference(Value,Reference,Max);
    }
    ]]

    return ref + (bit32.band(val - ref + max / 2, max - 1) - max / 2)
end

local function readInt(b, valMax)
    if valMax <= 1 then
        return 0
    end

    local total = 0
    local mask = 1

    while (mask + total < valMax) do
        if b.readBits(1)[1] == 1 then
            total = total + mask
        end
        mask = mask * 2
    end

    return total
end

local function readPktPayload(b)
    local pkt = {
        acks = {},
        bunches = {}
    }

    pkt.packetId = makeRelative(readInt(b, MAX_PACKETID), -1, MAX_PACKETID)

    while not b.isFinished() do
        local isAck = b.readField(1)[1]
        if not isAck then
            break
        end

        local ackPktId = makeRelative(readInt(b, MAX_PACKETID), -1, MAX_PACKETID)
        table.insert(pkt.acks, ackPktId)
    end

    while not b.isFinished() do
        local bunch = {}

        bunch.control = b.readField(1)[1]
        bunch.open = bunch.control and b.readField(1)[1] or false
        bunch.close = bunch.control and b.readField(1)[1] or false

        bunch.reliable = b.readField(1)[1]
        bunch.chanIdx = readInt(b, MAX_CHANNELS)
        bunch.chanSequence = bunch.reliable and makeRelative(readInt(b, MAX_CHSEQUENCE), -1, MAX_CHSEQUENCE) or 0
        bunch.chanType = (bunch.reliable or bunch.open) and readInt(b, CHTYPE_MAX) or CHTYPE_None

        -- Could be different?
        bunch.payloadSizeBits = readInt(b, 512 * 8)
        local payloadSizeBytes = math.floor(bunch.payloadSizeBits / 8)
        local payloadSizeBytesRem = bunch.payloadSizeBits % 8
        if payloadSizeBytesRem ~= 0 then
            print(string.format("bunch.payloadSizeBits (%d, %d bytes) not divisible by 8, not byte aligned",
                bunch.payloadSizeBits, payloadSizeBytes))
        end

        if bunch.payloadSizeBits > b.getLength() - b.getPointer() then
            print("bruh")
            table.insert(pkt.bunches, bunch)
            break
        end

        if bunch.payloadSizeBits > 0 then
            bunch.payload = b.readSetLengthString(payloadSizeBytes)

            if payloadSizeBytesRem ~= 0 then
                local payloadBuf = BitBuffer(bunch.payload)

                local remBits = b.readBits(payloadSizeBytesRem)
                for _, bit in ipairs(remBits) do
                    payloadBuf.writeBits(bit)
                end

                bunch.payload = payloadBuf.dumpString()
            end
        else
            bunch.payload = ""
        end

        table.insert(pkt.bunches, bunch)
    end

    return pkt
end

ioannes.onRecv = function(raw)
    ioannes.onSend = nil
    ioannes.onRecv = nil

    local pkt = ioannes.decode(raw.data)
    local payload = pkt.payload
    local len = #payload

    local b = BitBuffer(payload)
    local deserPkt = readPktPayload(b)
    print(LuaEncode(deserPkt, { Prettify = true }))

    return ioannes.encode(pkt)
end
