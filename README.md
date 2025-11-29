# SSH Log Analiz ve Brute Force Tespit Aracı

Linux sistemlerdeki SSH log dosyalarını (`/var/log/auth.log`) analiz ederek olası brute force saldırılarını tespit eden Python tabanlı bir araç.

## Özellikler

- ✅ SSH log dosyalarını otomatik parse etme
- ✅ IP bazlı brute force saldırı tespiti
- ✅ Zaman bazlı analiz (belirli bir süre içinde çok fazla deneme)
- ✅ Detaylı raporlar (JSON, CSV, HTML formatlarında)
- ✅ Risk seviyesi değerlendirmesi
- ✅ İstatistiksel analiz

## Gereksinimler

- Python 3.6 veya üzeri
- Linux işletim sistemi (auth.log dosyası için)
- Log dosyasına okuma erişimi

## Kurulum

1. Projeyi klonlayın veya indirin:
```bash
cd sshlog
```

2. Python'un yüklü olduğundan emin olun:
```bash
python3 --version
```

3. Script'i çalıştırılabilir yapın (opsiyonel):
```bash
chmod +x ssh_analyzer.py
```

## Kullanım

### Temel Kullanım

```bash
python ssh_analyzer.py --log /var/log/auth.log
```

### Tüm Parametreler

```bash
python ssh_analyzer.py \
  --log /var/log/auth.log \
  --output ./reports \
  --format all \
  --time-window 5 \
  --threshold 5
```

### Parametre Açıklamaları

- `--log`: Analiz edilecek log dosyasının yolu (varsayılan: `/var/log/auth.log`)
- `--output`: Raporların kaydedileceği dizin (varsayılan: `./reports`)
- `--format`: Rapor formatı - `json`, `csv`, `html` veya `all` (varsayılan: `all`)
- `--time-window`: Brute force tespiti için zaman penceresi (dakika, varsayılan: 5)
- `--threshold`: Şüpheli kabul edilecek minimum başarısız deneme sayısı (varsayılan: 5)

### Örnek Senaryolar

#### Sadece HTML raporu oluştur
```bash
python ssh_analyzer.py --log /var/log/auth.log --format html
```

#### Daha hassas tespit (10 dakikada 3 deneme)
```bash
python ssh_analyzer.py --log /var/log/auth.log --time-window 10 --threshold 3
```

#### Özel çıktı dizini
```bash
python ssh_analyzer.py --log /var/log/auth.log --output /tmp/ssh_reports
```

#### Test için örnek log dosyası
Eğer test etmek istiyorsanız, örnek bir log dosyası oluşturabilirsiniz:
```bash
# Örnek log dosyası oluştur
cat > test_auth.log << 'EOF'
Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 12345 ssh2
Jan 15 10:30:50 server sshd[12346]: Failed password for admin from 192.168.1.100 port 12346 ssh2
Jan 15 10:30:55 server sshd[12347]: Failed password for user from 192.168.1.100 port 12347 ssh2
Jan 15 10:31:00 server sshd[12348]: Failed password for root from 192.168.1.100 port 12348 ssh2
Jan 15 10:31:05 server sshd[12349]: Failed password for admin from 192.168.1.100 port 12349 ssh2
Jan 15 10:31:10 server sshd[12350]: Failed password for test from 192.168.1.100 port 12350 ssh2
EOF

# Analiz et
python ssh_analyzer.py --log test_auth.log
```

## Rapor Formatları

### JSON Raporu
Yapılandırılmış veri formatı, programatik işleme için uygundur:
```json
{
  "analysis_date": "2024-01-15T10:30:00",
  "statistics": { ... },
  "suspicious_ips": [ ... ]
}
```

### CSV Raporu
Excel veya diğer tablo uygulamalarında açılabilir format:
- IP Adresi
- Toplam Başarısız Deneme
- Toplam Başarılı Deneme
- Başarı Oranı
- Denenen Kullanıcılar
- İlk/Son Deneme Tarihleri

### HTML Raporu
Görsel ve interaktif web raporu:
- Renkli istatistik kartları
- Risk seviyesi göstergeleri
- Tablo formatında detaylı liste
- Modern ve responsive tasarım

## Brute Force Tespit Algoritması

Araç şu kriterlere göre brute force saldırılarını tespit eder:

1. **Zaman Penceresi Analizi**: Belirli bir zaman penceresi içinde (varsayılan: 5 dakika) çok fazla başarısız deneme yapan IP'ler tespit edilir.

2. **Eşik Değeri**: Bir IP adresi, zaman penceresi içinde belirlenen eşik değerinden (varsayılan: 5) fazla başarısız deneme yaparsa şüpheli olarak işaretlenir.

3. **IP Bazlı Analiz**: Her IP adresi için:
   - Toplam başarısız deneme sayısı
   - Toplam başarılı deneme sayısı
   - Denenen kullanıcı adları
   - İlk ve son deneme zamanları
   - Başarı oranı

4. **Risk Seviyesi**:
   - **Yüksek**: 50+ başarısız deneme
   - **Orta**: 20-49 başarısız deneme
   - **Düşük**: 5-19 başarısız deneme

## Çıktı Örnekleri

### Konsol Çıktısı
```
Log dosyası okunuyor: /var/log/auth.log
Toplam 1250 SSH olayı bulundu.
Brute force analizi yapılıyor (zaman penceresi: 5 dakika, eşik: 5)...
JSON raporu oluşturuldu: ./reports/ssh_analysis_20240115_103045.json
CSV raporu oluşturuldu: ./reports/ssh_analysis_20240115_103045.csv
HTML raporu oluşturuldu: ./reports/ssh_analysis_20240115_103045.html

============================================================
ANALİZ ÖZETİ
============================================================
Toplam Olay: 1250
Başarısız Deneme: 850
Başarılı Giriş: 400
Benzersiz IP: 45
Şüpheli IP: 12
============================================================
```

## Güvenlik Notları

- Bu araç sadece **raporlama** yapar, otomatik engelleme yapmaz
- Şüpheli IP'leri manuel olarak firewall kurallarıyla engellemeniz önerilir
- Düzenli olarak log analizi yaparak sisteminizi izleyin
- Başarılı girişlerin de analiz edilmesi önemlidir

## Sorun Giderme

### "Log dosyası bulunamadı" Hatası
- Log dosyasının yolunu kontrol edin
- Dosya izinlerini kontrol edin (okuma yetkisi gerekli)
- Root yetkisi gerekebilir: `sudo python ssh_analyzer.py --log /var/log/auth.log`

### "SSH olayı bulunamadı" Uyarısı
- Log dosyasında SSH (sshd) mesajları olup olmadığını kontrol edin
- Log formatının standart auth.log formatında olduğundan emin olun

### Yavaş Performans
- Büyük log dosyaları için analiz süresi artabilir
- Belirli bir tarih aralığı için log dosyasını filtreleyebilirsiniz

## Lisans

Bu proje eğitim ve güvenlik analizi amaçlıdır.

## Katkıda Bulunma

Öneriler ve hata bildirimleri için issue açabilirsiniz.

