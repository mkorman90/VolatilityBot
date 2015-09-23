rule Winsock__WSA : Sockets Winsock {
    meta:
        weight = 1
    strings:
        $WSASocket ="WSASocket"
        $WSASend ="WSASend"
        $WSARecv ="WSARecv"
        $WSAConnect ="WSAConnect"
        $WSAIoctl ="WSAIoctl"
        $WSAConnect ="WSAConnect"
    condition:
        any of them
}
