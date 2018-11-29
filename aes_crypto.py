from Crypto.Cipher import AES

text = bytes('ABCDEFGHIJKLMNOP', encoding='ASCII')
key = bytes('ABCDEFGHIJKLMNOP', encoding='ASCII')
mode = AES.MODE_CBC
iv = bytes('0' * 16, encoding='ASCII')

encryptor = AES.new(key, mode, iv)
decryptor = AES.new(key, mode, iv)

ciphertext = encryptor.encrypt(text)

text_de = decryptor.decrypt(ciphertext)

print('text=:', text)
print('ciphertext=:', ciphertext) #  b'\xfa\x18\x98R$Q\x92\x9fV]SPj\xab^\xab'
print('text_de=:', text_de)
