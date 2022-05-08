class Protocol:
    """
    //Regulations:
        //4 bytes of packet header

        //Integer takes up 4 bytes

        //String length bits in 2 bytes

        //Indefinite length of string

    """

    def __init__(self, bs=None):
        """
        //If bs is None, a packet needs to be created
        //Otherwise, it means that a packet needs to be parsed
        """
        if bs:
            self.bs = bytearray(bs)
        else:
            self.bs = bytearray(0)

    def get_int32(self):
        try:
            ret = self.bs[:4]
            self.bs = self.bs[4:]
            return int.from_bytes(ret, byteorder='little')
        except:
            raise Exception("Data exception!")

    def get_str(self):
        try:
            # Get string byte length (string length bit 2 bytes)
            length = int.from_bytes(self.bs[:2], byteorder='little')
            # Take the string again
            ret = self.bs[2:length + 2]
            # Delete the extracted part
            self.bs = self.bs[2 + length:]
            return ret.decode(encoding='utf8')
        except:
            raise Exception("Data exception!")

    def add_int32(self, val):
        bytes_val = bytearray(val.to_bytes(4, byteorder='little'))
        self.bs += bytes_val

    def add_str(self, val):
        bytes_val = bytearray(val.encode(encoding='utf8'))
        bytes_length = bytearray(
            len(bytes_val).to_bytes(2, byteorder='little'))
        self.bs += (bytes_length + bytes_val)

    def get_pck_not_head(self):
        return self.bs

    def get_pck_has_head(self):
        bytes_pck_length = bytearray(
            len(self.bs).to_bytes(4, byteorder='little'))
        return bytes_pck_length + self.bs


if __name__ == '__main__':
    p = Protocol()

    p.add_int32(666)
    p.add_str("How do you do")
    p.add_str("hello")
    p.add_int32(888)

    r = Protocol(p.get_pck_not_head())

    print(r.get_int32())
    print(r.get_str())
    print(r.get_str())
    print(r.get_int32())
