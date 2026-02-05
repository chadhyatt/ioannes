ioannes.onRecv = function(raw)
    local pkt = ioannes.decode(raw.data)
    local payload = pkt.payload
    local len = #payload

    local b = BitBuffer(payload)

    for i = 1, 7 do
        b.setPointer(i)
        print(tostring(i) .. ":\n" .. hexdump(b.readSetLengthString(b.getByteLength() - b.getPointerByte() - 1)))
    end

    return ioannes.encode(pkt)
end
--ioannes.onRecv = nil
