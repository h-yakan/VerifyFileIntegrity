# VerifyFileIntegrity

`VerifyFileIntegrity`, belirlediğiniz klasörlerdeki dosyaların **envanterini** (path, boyut, tarih, SHA256 hash) çıkaran ve daha sonra bu envanterle karşılaştırma yaparak **dosya değişikliklerini (yeni, silinmiş, değiştirilmiş)** raporlayan bir araçtır.  

Özellikle `.py`, `.env` gibi hassas dosyaların bütünlüğünü kontrol etmek için uygundur.

---

## Özellikler

- Dosya envanteri çıkarma (`build` komutu)  
- Önceki envantere göre dosya değişikliklerini kontrol etme (`check` komutu)  
- SHA256 hash ile bütünlük doğrulama  
- Raporlama: konsola veya dosyaya yazdırma  
- Birden fazla uzantıyı destekleme (`--ext .py --ext .env,.txt`)  

---

## Kurulum

Python 3.8+ gereklidir.

```bash
git clone <repo-url>
cd <repo-klasörü>
```

Opsiyonel olarak global komut gibi çalıştırmak için:
```bash
ln -s $(pwd)/verifyfileintegrity.py /usr/local/bin/verifyfileintegrity
```

---

## Kullanım

### 1. Envanter Oluşturma

Bir klasörü tarayıp dosya envanteri çıkarır:

```bash
python verifyfileintegrity.py build --root ./proje --output baseline.csv
```

Varsayılan uzantılar: `.py`, `.env`  
Kendi uzantılarınızı belirlemek için:  

```bash
python verifyfileintegrity.py build --root ./proje --ext .py --ext .txt,.md --output baseline.csv
```

Oluşan `baseline.csv` dosyasında şu bilgiler vardır:  
- path (göreceli dosya yolu)  
- size (bayt cinsinden boyut)  
- mtime_utc (son değişiklik tarihi, UTC ISO formatında)  
- sha256 (dosyanın SHA256 özeti)  

---

### 2. Envanter ile Karşılaştırma

Daha sonra aynı klasörü tekrar tarayıp değişiklikleri görmek için:  

```bash
python verifyfileintegrity.py check --root ./proje --input baseline.csv
```

Sonuç raporu konsola yazılır.  

Dosyaya kaydetmek için:  

```bash
python verifyfileintegrity.py check --root ./proje --input baseline.csv --report rapor.txt
```

---

## Çıktı Örneği

```
VerifyFileIntegrity Report
2025-09-04T15:00:00+00:00

Toplam Yeni Dosya: 1
Toplam Silinmiş Dosya: 2
Toplam Değiştirilmiş Dosya: 1

[Yeni Dosyalar]
+ yeni_dosya.py | 1234 B | 2025-09-04T14:59:00+00:00

[Silinmiş Dosyalar]
- eski_dosya.py | 567 B | 2025-09-01T10:00:00+00:00

[Değiştirilmis Dosyalar]
* config.env
  eski: 200 B | 2025-09-01T09:00:00+00:00 | a1b2c3d4e5f6...
  yeni: 220 B | 2025-09-04T14:58:00+00:00 | f6e5d4c3b2a1...
```

---

## Hata Kodları

- `0`: Başarılı çalıştı  
- `1`: Beklenmeyen hata  
- `2`: Dosya bulunamadı  
- `130`: Kullanıcı iptal etti (Ctrl+C)  

