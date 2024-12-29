const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const sqlite3 = require('sqlite3');
const fs = require('fs');
const path = require('path');

app.use(express.json()); // express'in json veri türünü kullanabilmesi içn
app.use(cookieParser()); // express'in cookie'leri kullanabilmesi için

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));

authenticator.options = { algorithm: 'sha256'};

const ingilizce_sozluk = new sqlite3.Database('./ingilizce_sozluk.db');
const almanca_sozluk = new sqlite3.Database('./almanca_sozluk.db');
const notlar = new sqlite3.Database('./notlar.db');
const ayarlar = new sqlite3.Database('./ayarlar.db');
const uygulama = "Kolay Erişim";

//ingilizce sözlük için her bir kelimeye id olacak şekilde create_table yap
ingilizce_sozluk.run('CREATE TABLE IF NOT EXISTS turkce (id TEXT PRIMARY KEY, kelime TEXT NOT NULL, anlam1 TEXT NOT NULL, anlam2 TEXT, anlam3 TEXT)');
ingilizce_sozluk.run('CREATE TABLE IF NOT EXISTS ingilizce (id TEXT PRIMARY KEY, kelime TEXT NOT NULL, anlam1 TEXT NOT NULL, anlam2 TEXT, anlam3 TEXT)');
almanca_sozluk.run('CREATE TABLE IF NOT EXISTS adjektiv(id TEXT PRIMARY KEY, adj TEXT, kom TEXT, sup TEXT, tr1 TEXT NOT NULL, tr2 TEXT, tr3 TEXT)');
almanca_sozluk.run('CREATE TABLE IF NOT EXISTS nomen(id TEXT PRIMARY KEY, sin TEXT, gen TEXT, plu TEXT, tr1 TEXT NOT NULL, tr2 TEXT, tr3 TEXT)');
almanca_sozluk.run('CREATE TABLE IF NOT EXISTS verb(id TEXT PRIMARY KEY, ver TEXT, dsk TEXT, pra TEXT, pa2 TEXT, tr1 TEXT NOT NULL, tr2 TEXT, tr3 TEXT)');
notlar.run('CREATE TABLE IF NOT EXISTS notlar (id TEXT PRIMARY KEY, baslik TEXT NOT NULL, icerik TEXT NOT NULL, tarih TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL , kategori TEXT NOT NULL)');
ayarlar.run('CREATE TABLE IF NOT EXISTS kullanicilar (id TEXT PRIMARY KEY, kullanici TEXT UNIQUE NOT NULL, yetki INTEGER NOT NULL, anahtar TEXT UNIQUE NOT NULL, hatali_giris INTEGER DEFAULT 0, son_hatali_giris INTEGER DEFAULT 0)');
ayarlar.get('SELECT * FROM kullanicilar WHERE kullanici = "admin"', (err, row) => {
  if (!row) {
    const adminAnahtar = authenticator.generateSecret(32);
    ayarlar.run('INSERT INTO kullanicilar (id, kullanici, yetki, anahtar) VALUES (?, "admin", 1, ?)', crypto.randomUUID(), adminAnahtar);
    karekodOlustur('admin', adminAnahtar).then(karekod => console.log("Admin: " + karekod));
  }
});
ayarlar.get('SELECT * FROM kullanicilar WHERE kullanici = "goruntuleyen"', (err, row) => {
  if (!row) {
    const goruntuleyenAnahtar = authenticator.generateSecret(32);
    ayarlar.run('INSERT INTO kullanicilar (id, kullanici, yetki, anahtar) VALUES (?, "goruntuleyen", 2, ?)',crypto.randomUUID(), goruntuleyenAnahtar);
    karekodOlustur('goruntuleyen', goruntuleyenAnahtar).then(karekod => console.log("Goruntuleyen: " + karekod));
  }
});

async function karekodOlustur(kullanici, anahtar) {
  return QRCode.toDataURL(authenticator.keyuri(kullanici, uygulama, anahtar));
}

function jwtOlustur(uuid, anahtar) {
  return jwt.sign({ uuid: uuid }, anahtar, { expiresIn: '1h' });
}

function jwtDogrula(token, anahtar) {
  try {
    const veri = jwt.verify(token, anahtar);
    return { basarili: true, veri: veri };
  } 
  catch (hata) {
    return { basarili: false, veri: hata.message };
  }
}

function ingilizceKelimeSec(dil) {
  return new Promise((resolve, reject) => {
    ingilizce_sozluk.all('SELECT * FROM '+dil+' ORDER BY RANDOM() LIMIT 1', (err, rows) => {
      let sozcuk = {};
      if (rows && rows.length > 0) {
        const anlamlar = [];
        if (rows[0].anlam1) anlamlar.push(rows[0].anlam1);
        if (rows[0].anlam2) anlamlar.push(rows[0].anlam2);
        if (rows[0].anlam3) anlamlar.push(rows[0].anlam3);
        sozcuk = { id: rows[0].id, kelime: rows[0].kelime, anlamlar: anlamlar }
      }
      resolve(sozcuk);
    });
  });
}

function almancaKelimeSec(tur) {
  return new Promise((resolve, reject) => {
    almanca_sozluk.all('SELECT * FROM '+tur+' ORDER BY RANDOM() LIMIT 1', (err, rows) => {
      let sozcuk = {};
      if (rows && rows.length > 0) {
        const anlamlar = [];
        if(tur == "adjektiv"){
          sozcuk["adjektiv"] = rows[0].adj || "";
          sozcuk["komparativ"] = rows[0].kom || "";
          sozcuk["superlativ"] = rows[0].sup || "";
        }
        else if(tur == "nomen"){
          sozcuk["singular"] = rows[0].sin || "";
          sozcuk["genitiv"] = rows[0].gen || "";
          sozcuk["plural"] = rows[0].plu || "";
        }
        else if(tur == "verb"){
          sozcuk["verb"] = rows[0].ver || "";
          sozcuk["singular3"] = rows[0].dsk || "";
          sozcuk["praeteritum"] = rows[0].praeteritum || "";
          sozcuk["partizip2"] = rows[0].pa2 || "";
        }
        if (rows[0].tr1) anlamlar.push(rows[0].tr1);
        if (rows[0].tr2) anlamlar.push(rows[0].tr2);
        if (rows[0].tr3) anlamlar.push(rows[0].tr3);
        sozcuk["id"] = rows[0].id;
        sozcuk["tur"] = tur;
        sozcuk["anlamlar"] = anlamlar;
      }
      resolve(sozcuk);
    });
  });
}

const cookieDogrula = (req, res, next) => {
  const token = req.cookies.token;
  const uuid = req.cookies.userid;
  const r = "/kullanici/giris?r="+req.url;
  if (!token || !uuid) {
    return res.redirect(r);
  }
  ayarlar.get('SELECT * FROM kullanicilar WHERE id = ?', uuid, (err, row) => {
    if (!row) {
      return res.redirect(r);
    }
    const anahtar = row.anahtar;
    const yetki = row.yetki;
    let hatali_giris = row.hatali_giris;
    const son_hatali_giris = row.son_hatali_giris;
    if(hatali_giris >= 5){
      if(Date.now() - son_hatali_giris < 30000){
        return res.redirect(r);
      }
      else{
        ayarlar.run('UPDATE kullanicilar SET hatali_giris = 0 WHERE id = ?', uuid);
        hatali_giris = 0;
      }
    }
    const yanit = jwtDogrula(token, anahtar);
    if (yanit.basarili && yanit.veri.uuid === uuid) {
      req.yetki = yetki;
      next();
    } 
    else {
      if(hatali_giris == 0){
        ayarlar.run('UPDATE kullanicilar SET hatali_giris = 1, son_hatali_giris = ? WHERE id = ?', Date.now(), uuid);
      }
      else{
        ayarlar.run('UPDATE kullanicilar SET hatali_giris = hatali_giris + 1 WHERE id = ?', uuid);
      } 
      return res.redirect(r);
    }
  });
}

app.post('/kullanici/giris', (req, res) => {
    const { kullanici, sifre } = req.body;
  
    if (!kullanici || !sifre) {
      return res.status(400).json({ hata: 'Kullanıcı adı veya şifre eksik veya hatalı! ' });
    }
    
    ayarlar.get('SELECT * FROM kullanicilar WHERE kullanici = ?', kullanici, (err, row) => {
      if (!row) {
        return res.status(404).json({ hata: 'Kullanıcı adı veya şifre eksik veya hatalı! ' });
      }
      const anahtar = row.anahtar;
      const yetki = row.yetki;
      let hatali_giris = row.hatali_giris;
      const son_hatali_giris = row.son_hatali_giris;
      const uuid = row.id;
      if(hatali_giris >= 5){
        if(Date.now() - son_hatali_giris < 30000){
          return res.status(403).json({ hata: 'Kullanıcı adı veya şifre eksik veya hatalı! ' });
        }
        else{
          ayarlar.run('UPDATE kullanicilar SET hatali_giris = 0 WHERE id = ?', uuid);
          hatali_giris = 0;
        }
      }
      if (authenticator.verify({ token: sifre, secret: anahtar })) {
        const token = jwtOlustur(uuid, anahtar);
        res.cookie('token', token, { httpOnly: true, sameSite: 'strict'/*, secure: true*/, maxAge: 3600 * 1000 });
        res.cookie('userid', uuid, { httpOnly: true, sameSite: 'strict'/*, secure: true*/, maxAge: 3600 * 1000 });
        return res.json({ mesaj: 'Giriş başarılı! ' });
      } else {
        if(hatali_giris == 0){  
          ayarlar.run('UPDATE kullanicilar SET hatali_giris = 1, son_hatali_giris = ? WHERE id = ?', Date.now(), uuid);
        }
        else{
          ayarlar.run('UPDATE kullanicilar SET hatali_giris = hatali_giris + 1 WHERE id = ?', uuid);
        } 
        return res.status(401).json({ hata: 'Kullanıcı adı veya şifre eksik veya hatalı! ' });
      }
  });
});

app.get('/kullanici/giris', (req, res) => {
  res.sendFile(__dirname + '/www/kullanici/giris.html');
});
app.get('/', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/index.html');
}); 
app.get('/ingilizce-sozluk', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/ingilizce_sozluk/index.html');
}); 
app.get('/almanca-sozluk', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/almanca_sozluk/index.html');
}); 
app.get('/notlar', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/notlar/index.html');
}); 

app.get('/ingilizce-sozluk/ara', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/ingilizce_sozluk/ara.html');
});
app.get('/ingilizce-sozluk/ekle', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/ingilizce_sozluk/ekle.html');
});
app.get('/ingilizce-sozluk/sor', cookieDogrula,   (req, res) => {
  res.sendFile(__dirname + '/www/ingilizce_sozluk/sor.html');
});

app.get('/almanca-sozluk/ara', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/almanca_sozluk/ara.html');
});
app.get('/almanca-sozluk/ekle', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/almanca_sozluk/ekle.html');
});
app.get('/almanca-sozluk/sor', cookieDogrula,   (req, res) => {
  res.sendFile(__dirname + '/www/almanca_sozluk/sor.html');
});

app.get('/notlar/not-ekle', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/notlar/not_ekle.html');
});
app.get('/notlar/not-guncelle', cookieDogrula, (req, res) => {
  res.sendFile(__dirname + '/www/notlar/not_guncelle.html');
});

app.post('/ingilizce-sozluk/ara', cookieDogrula, (req, res) => {
  const { kelime } = req.body;
  if (!kelime) {
    return res.status(400).json({ hata: 'Kelime eksik! ' });
  }
  let kelimeler = [];
  new Promise((resolve, reject) => {
    let gecici = [];
    for(let i=0; i<4; i++){
      gecici.push("%"+kelime+"%");
    }
    ingilizce_sozluk.all('SELECT * FROM ingilizce WHERE anlam1 LIKE ? OR anlam2 LIKE ? OR anlam3 LIKE ? OR kelime LIKE ? ORDER BY kelime ASC', gecici, (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          const anlamlar = [];
          if (row.anlam1) anlamlar.push(row.anlam1);
          if (row.anlam2) anlamlar.push(row.anlam2);
          if (row.anlam3) anlamlar.push(row.anlam3);
          kelimeler.push({ id: row.id, kelime: row.kelime, anlamlar: anlamlar });
        });
      }
      resolve();
    });
  }).then(() => {
    let gecici = [];
    for(let i=0; i<4; i++){
      gecici.push("%"+kelime+"%");
    }
    ingilizce_sozluk.all('SELECT * FROM turkce WHERE anlam1 LIKE ? OR anlam2 LIKE ? OR anlam3 LIKE ? OR kelime LIKE ? ORDER BY kelime ASC', gecici, (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          const anlamlar = [];
          if (row.anlam1) anlamlar.push(row.anlam1);
          if (row.anlam2) anlamlar.push(row.anlam2);
          if (row.anlam3) anlamlar.push(row.anlam3);
          kelimeler.push({ id: row.id, kelime: row.kelime, anlamlar: anlamlar });
        });
      }
      return res.json({ kelimeler: kelimeler });
    });
  });
});
app.delete('/ingilizce-sozluk/sil', cookieDogrula, (req, res) => {
  const { id } = req.body;
  if (!id || !req.yetki) {
    return res.status(400).json({ hata: 'Kullanici veya yetki bilgisi eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  new Promise((resolve, reject) => {
    ingilizce_sozluk.run('DELETE FROM turkce WHERE id = ?', id, (err) => {
      resolve();
    });
  }).then(() => {
    ingilizce_sozluk.run('DELETE FROM ingilizce WHERE id = ?', id, (err) => {
      return res.json({ mesaj: 'Silme işlemi başarılı! ' });
    });
  });
});
app.post('/ingilizce-sozluk/sor', cookieDogrula, async (req, res) => {
  let dil = Math.floor(Math.random() * 2);
  let kelime = await ingilizceKelimeSec(dil == 0 ? 'turkce' : 'ingilizce');
  if(kelime.id){
    return(res.json(kelime));
  }
  kelime = await ingilizceKelimeSec(dil == 0 ? 'ingilizce' : 'turkce');
  if(kelime.id){
    return res.json(kelime);
  }
  else{
    return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: sor01 ' });
  }
});
app.post('/ingilizce-sozluk/ekle', cookieDogrula, (req, res) => {
  const { kelime, anlamlar } = req.body;
  let dil = req.body.dil;
  if(!kelime || !anlamlar || !dil || !req.yetki){
    return res.status(400).json({ hata: 'Kelime, anlam veya dil bilgileri eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  let anlam1 = anlamlar[0];
  let anlam2 = "";
  let anlam3 = "";
  if(anlamlar.length>1){
    anlam2 = anlamlar[1];
    if(anlamlar.length>2){
      anlam3 = anlamlar[2];
    }
  }
  if(dil == "tr->en"){
    dil = 'turkce';
  }
  else if(dil == "en->tr"){
    dil = 'ingilizce';
  }
  else{
    return res.status(400).json({ hata: 'Dil bilgisi hatalı! ' });
  }
  const id = crypto.randomUUID();
  ingilizce_sozluk.run('INSERT INTO '+dil+' (id, kelime, anlam1, anlam2, anlam3) VALUES (?, ?, ?, ?, ?)', id, kelime, anlam1, anlam2, anlam3, (err) => {
    if (err) {
      return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: ekle01 ' });
    }
    else{
      return res.json({ mesaj: 'Ekleme işlemi başarılı! ' });
    }
  });
});

app.post('/notlar/tum-notlar', cookieDogrula, (req, res) => {
  notlar.all('SELECT * FROM notlar ORDER BY tarih DESC', (err, rows) => {
    let notlar = [];
    if (rows && rows.length > 0) {
      rows.forEach(row => {
        notlar.push({ notId: row.id, baslik: row.baslik, icerik: row.icerik, tarih: row.tarih, kategori: row.kategori });
      });
    }
    return res.json({ notlar: notlar });
  });
});
app.delete('/notlar/not-sil', cookieDogrula, (req, res) => {
  const { notId } = req.body;
  if (!notId || !req.yetki) {
    return res.status(400).json({ hata: 'Kullanici veya yetki bilgisi eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  notlar.run('DELETE FROM notlar WHERE id = ?', notId, (err) => {
    return res.json({ mesaj: 'Silme işlemi başarılı! ' });
  });
});
app.post('/notlar/not-ekle', cookieDogrula, (req, res) => {
  const { baslik, icerik } = req.body;
  if (!baslik || !icerik) {
    return res.status(400).json({ hata: 'Başlık veya içerik bilgileri eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  let kategori = req.body.kategori || "Genel";
  const notId = crypto.randomUUID();
  notlar.run('INSERT INTO notlar (id, baslik, icerik, kategori) VALUES (?, ?, ?, ?)', notId, baslik, icerik, kategori, (err) => {
    if (err) {
      return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: notEkle01 ' });
    }
    else{
      return res.json({ mesaj: 'Ekleme işlemi başarılı! ' });
    }
  });
});
app.put('/notlar/not-guncelle', cookieDogrula, (req, res) => {
  const { notId, baslik, icerik } = req.body;
  if (!notId || !baslik || !icerik || !req.yetki) {
    return res.status(400).json({ hata: 'Not ID, başlık veya içerik bilgileri eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  let kategori = req.body.kategori || "Genel";
  notlar.run('UPDATE notlar SET baslik = ?, icerik = ?, kategori = ? WHERE id = ?', baslik, icerik, kategori, notId, (err) => {
    if (err) {
      return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: notGuncelle01 ' });
    }
    else{
      return res.json({ mesaj: 'Güncelleme işlemi başarılı! ' });
    }
  });
});
app.post('/notlar/not-getir', cookieDogrula, (req, res) => {
  const { notId } = req.body;
  if (!notId) {
    return res.status(400).json({ hata: 'Not ID bilgisi eksik! ' });
  }
  notlar.get('SELECT * FROM notlar WHERE id = ?', notId, (err, row) => {
    if (!row) {
      return res.status(404).json({ hata: 'Not bulunamadı! ' });
    }
    return res.json({ baslik: row.baslik, icerik: row.icerik, kategori: row.kategori });
  });
});

app.post('/almanca-sozluk/ara', cookieDogrula, (req, res) => {
  const { kelime } = req.body;
  if (!kelime) {
    return res.status(400).json({ hata: 'Kelime eksik! ' });
  }
  let adjektiv = [];
  let nomen = [];
  let verb = [];
  new Promise((resolve, reject) => {
    let gecici = [];
    for(let i=0; i<6; i++){
      gecici.push("%"+kelime+"%");
    }
    almanca_sozluk.all('SELECT * FROM adjektiv WHERE tr1 LIKE ? OR tr2 LIKE ? OR tr3 LIKE ? OR adj LIKE ? OR kom LIKE ? OR sup LIKE ? ORDER BY adj ASC', gecici, (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          const anlamlar = [];
          if (row.tr1) anlamlar.push(row.tr1);
          if (row.tr2) anlamlar.push(row.tr3);
          if (row.tr3) anlamlar.push(row.tr3);
          const adj = row.adj || "";
          const komparativ = row.kom || "";
          const superlativ = row.sup || "";
          adjektiv.push({ id: row.id, adjektiv:adj, komparativ, superlativ , anlamlar });
        });
      }
      resolve();
    });
  }).then(() => {
    let gecici = [];
    for(let i=0; i<6; i++){
      gecici.push("%"+kelime+"%");
    }
    almanca_sozluk.all('SELECT * FROM nomen WHERE tr1 LIKE ? OR tr2 LIKE ? OR tr3 LIKE ? OR sin LIKE ? OR gen LIKE ? OR plu LIKE ? ORDER BY sin ASC', gecici, (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          const anlamlar = [];
          if (row.tr1) anlamlar.push(row.tr1);
          if (row.tr2) anlamlar.push(row.tr2);
          if (row.tr3) anlamlar.push(row.tr3);
          const singular = row.sin || "";
          const genitiv = row.gen || "";
          const plural = row.plu || "";
          nomen.push({ id: row.id, singular, genitiv, plural, anlamlar });
        });
      }
      return;
    });
  }).then(() => {
    let gecici = [];
    for(let i=0; i<7; i++){
      gecici.push("%"+kelime+"%");
    }
    almanca_sozluk.all('SELECT * FROM verb WHERE tr1 LIKE ? OR tr2 LIKE ? OR tr3 LIKE ? OR ver LIKE ? OR dsk LIKE ? OR pra LIKE ? OR pa2 LIKE ? ORDER BY ver ASC', gecici, (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          const anlamlar = [];
          if (row.tr1) anlamlar.push(row.tr1);
          if (row.tr2) anlamlar.push(row.tr2);
          if (row.tr3) anlamlar.push(row.tr3);
          const ver = row.ver || "";
          const singular3 = row.dsk || "";
          const praeteritum = row.pra || "";
          const partizip2 = row.pa2 || "";
          verb.push({ id: row.id, verb: ver, singular3, praeteritum, partizip2, anlamlar });
        });
      }
      return res.json({ adjektiv, nomen, verb });
    });
  });
});
app.delete('/almanca-sozluk/sil', cookieDogrula, (req, res) => {
  const { id } = req.body;
  if (!id || !req.yetki) {
    return res.status(400).json({ hata: 'Kullanici veya yetki bilgisi eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  new Promise((resolve, reject) => {
    almanca_sozluk.run('DELETE FROM adjektiv WHERE id = ?', id, (err) => {
      resolve();
    });
  }).then(() => {
    almanca_sozluk.run('DELETE FROM nomen WHERE id = ?', id, (err) => {
      return;
    })
  }).then(() => {
    almanca_sozluk.run('DELETE FROM verb WHERE id = ?', id, (err) => {
      return res.json({ mesaj: 'Silme işlemi başarılı! ' });
    });
  });
});
app.post('/almanca-sozluk/sor', cookieDogrula, async (req, res) => {
  let tur = Math.floor(Math.random() * 3);
  let kelime = await almancaKelimeSec(tur == 0 ? 'adjektiv' : (tur == 1 ? 'nomen' : 'verb'));
  if(kelime.id){
    return(res.json(kelime));
  }
  kelime = await almancaKelimeSec(tur == 0 ? 'nomen' : (tur == 1 ? 'verb' : 'adjektiv'));
  if(kelime.id){
    return res.json(kelime);
  }
  kelime = await almancaKelimeSec(tur == 0 ? 'verb' : (tur == 1 ? 'adjektiv' : 'nomen'));
  if(kelime.id){
    return res.json(kelime);
  }
  else{
    return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: sor01 ' });
  }
});
app.post('/almanca-sozluk/ekle', cookieDogrula, (req, res) => {
  const { turkce } = req.body;
  let tur = req.body.tur;
  if(!turkce || !tur || !req.yetki){
    return res.status(400).json({ hata: 'Kelime, anlam veya dil bilgileri eksik! ' });
  }
  if(req.yetki > 1){
    return res.status(403).json({ hata: 'Bu işlem için yetkiniz yok! ' });
  }
  let anlam1 = turkce[0]; 
  let anlam2 = "";
  let anlam3 = "";
  if(turkce.length>1){
    anlam2 = turkce[1];
    if(turkce.length>2){
      anlam3 = turkce[2];
    }
  }
  const id = crypto.randomUUID();
  if(tur == "adj"){
    if(!req.body.adjektiv && !req.body.komparativ && !req.body.superlativ){
      return res.status(400).json({ hata: 'Kelime, anlam veya dil bilgileri eksik! ' });
    }
    const adjektiv = req.body.adjektiv || "";
    const komparativ = req.body.komparativ || "";
    const superlativ = req.body.superlativ || "";
    almanca_sozluk.run('INSERT INTO adjektiv (id, adj, kom, sup, tr1, tr2, tr3) VALUES (?, ?, ?, ?, ?, ?, ?)'
      , id, adjektiv, komparativ, superlativ, anlam1, anlam2, anlam3, (err) => {
      if (err) {
        return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: ekle01 ' });
      }
      else{
        return res.json({ mesaj: 'Ekleme işlemi başarılı! ' });
      }
    });
  }
  else if(tur == "nom"){
    if(!req.body.singular && !req.body.genitiv && !req.body.plural){
      return res.status(400).json({ hata: 'Kelime, anlam veya dil bilgileri eksik! ' });
    }
    const singular = req.body.singular || "";
    const genitiv = req.body.genitiv || "";
    const plural = req.body.plural || "";
    almanca_sozluk.run('INSERT INTO nomen (id, sin, gen, plu, tr1, tr2, tr3) VALUES (?, ?, ?, ?, ?, ?, ?)'
      , id, singular, genitiv, plural, anlam1, anlam2, anlam3, (err) => {
      if (err) {
        return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: ekle01 ' });
      }
      else{
        return res.json({ mesaj: 'Ekleme işlemi başarılı! ' });
      }
    });
  }
  else if(tur == "ver"){
    if(!req.body.verb && !req.body.singular3 && !req.body.praeteritum && !req.body.partizip2){
      return res.status(400).json({ hata: 'Kelime, anlam veya dil bilgileri eksik! ' });
    }
    const verb = req.body.verb || "";
    const singular3 = req.body.singular3 || "";
    const praeteritum = req.body.praeteritum || "";
    const partizip2 = req.body.partizip2 || "";
    almanca_sozluk.run('INSERT INTO verb (id, ver, dsk, pra, pa2, tr1, tr2, tr3) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      , id, verb, singular3, praeteritum, partizip2, anlam1, anlam2, anlam3, (err) => {
      if (err) {
        return res.status(500).json({ hata: 'Sunucu hatası, hata kodu: ekle01 ' });
      }
      else{
        return res.json({ mesaj: 'Ekleme işlemi başarılı! ' });
      }
    });
  }
  else{
    return res.status(400).json({ hata: 'Kelime türü bilgisi hatalı! ' });
  }
});

app.get('/yedekle', cookieDogrula, (req, res) => {
  const { vt } = req.query;
  if (!vt || !req.yetki || req.yetki > 1) {
    res.status(404).json({mesaj: 'Aradığınız sayfa bulunamadı! '});
  }
  let dosya = ""; 
  switch(vt){
    case "ingilizce":
      dosya = "ingilizce_sozluk";
      break;
    case "almanca":
      dosya = "almanca_sozluk";
      break;
    case "notlar":
      dosya = "notlar";
      break;
    default:
      res.status(404).json({mesaj: 'Aradığınız sayfa bulunamadı! '});
  }
  dosya = vt + '.db';
  const dosyaYol = path.join(__dirname, dosya);
  if (fs.existsSync(dosyaYol)) {
    res.download(dosyaYol, dosya);
  } else {
    res.status(404).json({mesaj: 'Dosya bulunamadı! '});
  }
});

app.get('*', (req, res) => {
    res.status(404).json({mesaj: 'Aradığınız sayfa bulunamadı! '});
});
app.post('*', (req, res) => {
  res.status(404).json({mesaj: 'Aradığınız sayfa bulunamadı! '});
});