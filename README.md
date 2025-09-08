## VerifyFileIntegrity

Basit ve hızlı bir şekilde dizin içeriğinin bütünlüğünü doğrulamak için dosya envanteri (path, size, mtime, sha256) oluşturur ve bu envantere göre değişiklikleri raporlar.

### Kurulum
- Python 3.8+ gerekir. Ek paket yoktur (standart kütüphane).

### Kullanım
Komutlar iki alt başlıktan oluşur: `build` ve `check`.

Global seçenekler:
- `--config`: INI formatında ayar dosyasının yolu. Varsayılan olarak çalışma dizinindeki `verify_file_integrity.ini` aranır.
- `-v`/`-vv`: Daha ayrıntılı log çıktısı (INFO/DEBUG)
- `-q`/`-qq`: Daha sessiz çıktı (WARNING/ERROR)
- `--log-file`: Logların dosyaya yazılması (config’teki `log_file` varsa config önceliklidir)

#### Envanter oluşturma (build)
```
py verify_file_integrity.py build --output inventory.csv
```

Config ile:
```
py verify_file_integrity.py --config verify_file_integrity.ini build
```

`build` komutu sonunda envanter CSV dosyası oluşur.

#### Doğrulama (check)
```
py verify_file_integrity.py check --input inventory.csv
```

İsteğe bağlı:
- `--root`: Taranacak kök dizin (varsayılan: `.` veya configteki değer)
- `--ext`: Dahil edilecek uzantılar. Birden fazla kez verilebilir veya virgülle ayrılabilir.
  - Örnek: `--ext .py --ext .env,.txt`



Config ile:
```
py verify_file_integrity.py --config verify_file_integrity.ini check
```

Komut sonunda özet ve (verildiyse) rapor üretilir.

İsteğe bağlı:
- `--root`: Taranacak kök dizin (varsayılan: `.` veya configteki değer)
- `--ext`: Dahil edilecek uzantılar (envanter ile uyumlu olması önerilir)
- `--report`: Metin raporunu dosyaya yaz (verilmezse konsola yazılır)

### Config Dosyası (INI)
Varsayılan olarak çalışma dizinindeki `verify_file_integrity.ini` dosyası kullanılır. Farklı bir dosya için `--config` verin.

Öncelik kuralları:
- Parametreler için: CLI > Config
- Log dosyası için: Config (`[build]/[check] log_file` > `[logging] log_file`) > CLI `--log-file`

Örnek `verify_file_integrity.ini`:
```ini
[build]
root = .
ext = .py,.env,.txt
output = inventory.csv
# log_file = logs\\build.log

[check]
root = .
ext = .py,.env,.txt
input = inventory.csv
report = report.txt
# log_file = logs\\check.log

[logging]
log_file = logs\\app.log
```

### Notlar
- `build` için `output` zorunludur (CLI veya config).
- `check` için `input` zorunludur (CLI veya config).
- Uzantılar (`--ext` veya `ext`) boş verilirse varsayılan olarak `{.py, .env}` kullanılır.

### Örnek Akış
1) Envanteri oluşturun:
```
py verify_file_integrity.py --config verify_file_integrity.ini -v build
```

2) Değişiklikleri kontrol edin ve rapor üretin:
```
py verify_file_integrity.py --config verify_file_integrity.ini -vv check
```

Dosyaya log yazma (CLI ile):
```
py verify_file_integrity.py --config verify_file_integrity.ini --log-file logs\\run.log build
```
Config’te log_file tanımlıysa CLI `--log-file` yerine config’teki dosyaya yazılır.

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

