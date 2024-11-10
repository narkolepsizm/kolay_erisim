from PIL import Image
import io
import base64
import sqlite3
import qrcode
import urllib.parse

kullanici = 'admin'
uygulama = "Kolay Erişim"
conn = sqlite3.connect('./ayarlar.db')
cursor = conn.execute("SELECT kullanici, anahtar FROM kullanicilar WHERE kullanici = '"+kullanici+"'")
row = cursor.fetchone()
anahtar = row[1]
url = "otpauth://totp/"+urllib.parse.quote(uygulama)+":"+urllib.parse.quote(kullanici)+"?secret="+urllib.parse.quote(anahtar)+"&period=30&digits=6&algorithm=SHA256&issuer="+urllib.parse.quote(uygulama)
qrcode.make(url).show()
b64str = ""
#Image.open(io.BytesIO(base64.b64decode(b64str))).show()
conn.close()