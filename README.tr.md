# LinuxPi (π)

Linux için ayrıcalık yükseltme (privilege escalation) çerçevesi sunar — sistemdeki yükseltme vektörlerini kapsamlı analiz eder.

> **YASAL UYARI:** Bu araç **yalnızca yetkili penetrasyon testi ve güvenlik değerlendirmeleri** içindir. İzinsiz kullanım kesinlikle yasaktır.

**English:** [README.md](README.md)

---

## Mimari

```
linuxpi/
├── linuxpi.sh          # Ana giriş noktası
├── README.md           # Belgeler (English)
├── README.tr.md        # Belgeler (Türkçe)
├── core/
│   ├── main.sh                # Orkestrasyon
│   ├── detector.sh            # Sistem, konteyner, VM, bulut algılama
│   ├── analyzer.sh            # CVE eşleme, CVSS skorlama, GTFOBins
│   ├── enumerator.sh          # Modül yönetimi ve sıra
│   ├── exploiter.sh           # Otomatik sömürü motoru
│   └── reporter.sh            # Çoklu rapor biçimi (text/json/html/xml/md)
├── modules/
│   ├── kernel/          # CVE, sysctl, modül; kernel_research.sh (CONFIG/mitigasyon bağlamı)
│   ├── sudo/            # Sudo yapılandırması, CVE, ayrıcalık analizi
│   ├── suid/            # SUID/SGID, yetenekler, RPATH/RUNPATH
│   ├── cron/            # Cron, systemd zamanlayıcı, at işleri
│   ├── credentials/     # Kimlik bilgisi toplama (SSH, DB, bulut, DevOps)
│   ├── network/         # Ağ, NFS, güvenlik duvarı
│   ├── containers/      # Docker/K8s/LXC kaçış algılama
│   ├── services/        # Servisler, süreçler, yazılım
│   └── security/        # MAC, PATH ele geçirme, kabuk profili, doas
├── database/            # CVE, EPSS, GTFOBins veri tabanları
├── utils/               # Renkler, günlük, yardımcılar, argüman ayrıştırma
├── scripts/             # GTFOBins veritabanı üretim betiği
├── tests/               # Exploit motoru ve kernel CVE eşleme testleri
├── output/templates/    # HTML rapor şablonu
└── Makefile             # Derleme, test, lint ve sürüm yardımcıları
```

## Özellikler

### Tarama modülleri (12 modül)

| Modül | Açıklama |
|--------|-------------|
| `user` | Kullanıcı bağlamı, grup üyelikleri, ayrıcalık analizi |
| `kernel` | Çekirdek CVE (67+), sysctl, SMEP/SMAP/KASLR |
| `sudo` | Sudo sürüm CVE, kurallar, NOPASSWD, Baron Samedit vb. |
| `suid` | SUID/SGID tarama, GTFOBins eşlemesi, RPATH/RUNPATH |
| `capabilities` | Linux capabilities (tehlikeli yetenekler) |
| `cron` | Cron, systemd timer, wildcard enjeksiyonu, PATH ele geçirme |
| `credentials` | SSH, geçmiş, yapılandırma, DB, bulut, DevOps/IaC, git |
| `network` | Arayüz, port, NFS, güvenlik duvarı, DNS |
| `containers` | Docker soketi, ayrıcalıklı konteyner, K8s SA, namespace |
| `services` | Çalışan servisler, yazılabilir unit dosyaları |
| `filesystem` | Herkese yazılabilir dizinler, hassas dosyalar, mount bayrakları |
| `security` | AppArmor/SELinux, PATH, kabuk profilleri, doas |

### CVE veri tabanları

- **67+ çekirdek CVE** (2010–2026): Dirty COW, Dirty Pipe, PwnKit, nf_tables UAF, io_uring, eBPF, CopyFail, Dirty Frag, CIFSwitch…
- **15+ sudo CVE**: Baron Samedit, UID bypass, pwfeedback taşması…
- **Polkit, glibc, snapd, runc, PackageKit, CIFS/cifs.upcall** için özel kontroller
- **GTFOBins** ([gtfobins.org](https://gtfobins.org/)): **sudo**, **SUID** ve **capabilities** için tekniklerin aynası; güncellemek için: `make update-gtfobins`

### 2026 güncel LPE kapsamı

LinuxPi, Mart-Haziran 2026 advisory döneminde yayımlanan yerel yetki yükseltme kontrollerini de içerir:

| CVE / Ad | Tespit yöntemi |
|----------|----------------|
| `CVE-2026-31431` CopyFail | Kernel stable dal aralığı + AF_ALG / `algif_aead` bağlamı |
| `CVE-2026-43284` Dirty Frag ESP | Kernel stable dal aralığı + ESP/XFRM ve user namespace bağlamı |
| `CVE-2026-43500` Dirty Frag RxRPC | Kernel stable dal aralığı + RxRPC config/modül bağlamı |
| `CVE-2026-46300` Fragnesia | Kernel stable dal aralığı + ESP/XFRM bağlamı |
| `CVE-2026-46333` ssh-keysign-pwn | Kernel stable dal aralığı + ptrace ve SUID/root helper bağlamı |
| `CVE-2026-31635` DirtyDecrypt | Kernel stable dal aralığı + RxRPC/RxGK bağlamı |
| `CVE-2026-46243` CIFSwitch | CIFS modülü, `cifs.upcall`, `cifs.spnego` request-key zinciri |
| `CVE-2026-41651` Pack2TheRoot | PackageKit sürümü ve servis/araç varlığı |

Yeni kernel advisory’leri tek geniş min/max pencere yerine stable dal bazlı aralıklarla tutulur. Böylece yamalı stable sürümlerde yanlış pozitifler azalır; çalışma zamanı önkoşulları ise bulgu kanıtına eklenir.

### EPSS + CVSS öncelik skorlama

Her bulgu makine tarafından okunabilir skorlarla zenginleştirilir:

- **CVSS temel skoru** + vektör dizisi (NVD v3.1)
- **EPSS** — önümüzdeki 30 günde sömürü olasılığı (FIRST.org)
- **Öncelik skoru** (0–10): `(CVSS × 0.35) + (EPSS × 10 × 0.40) + (exploit_avail × 0.25)`
- **Öncelik katmanı**: IMMINENT (≥8) / LIKELY (≥6) / POSSIBLE (≥4) / UNLIKELY (≥2) / MINIMAL

### Gelişmiş bulgu birleştirme

- **CVE tabanlı birleştirme**: Aynı CVE birden fazla modülde → tek bulgu, en yüksek şiddet
- **Başlık normalizasyonu**: Büyük/küçük harf duyarsız, önek temizleme
- **Detay birleştirme**: Aynı zafiyeti gören modüllerin bağlamının birleştirilmesi

### Zenginleştirilmiş bulgu alanları

| Alan | Açıklama |
|------|----------|
| **Evidence** | Kanıt: dosya yolları, izinler, değerler |
| **Remediation** | Düzeltme önerisi |
| **MITRE ATT&CK** | Teknik kimliği |
| **References** | NVD, MITRE, GTFOBins bağlantıları |
| **Credential hints** | Varsayılan: maskeleme; **`--report-full-secrets`** ile düz metin (yüksek sızıntı riski) |

### Rapor biçimleri

- **Text** — Terminal özeti, kanıt maddeleri, MITRE, CVSS/EPSS
- **JSON** — SIEM uyumlu yapı
- **HTML** — Koyu tema pano, kanıt/remedy panelleri
- **XML** — Yapılandırılmış etiketler
- **Markdown** — Dokümantasyon için

### Diğer

- Şiddete göre sıralama, ilerleme çubuğu, modül süreleri
- **Exploit modu** — etkileşimli menü; **`--run`** — tarama sonrası kabuk sınıflı vektörleri sırayla, onaysız dener (`sudo` → `sudo -n` ile parola sormaz; perl gerekir)

## Kurulum

**HTTPS** veya **SSH** ile klonlayın ([GitHub SSH anahtarı](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)):

```bash
git clone https://github.com/cumakurt/linuxpi.git
# veya
git clone git@github.com:cumakurt/linuxpi.git

cd linuxpi
chmod +x linuxpi.sh
```

Depoda `build/` ve `dist/` yoktur; tek dosya için `make standalone` çalıştırın veya doğrudan `linuxpi.sh` kullanın.

### Tek dosya (standalone) derleme

```bash
make standalone    # Tüm modüller tek bash dosyasında
make minimal       # Sadece kernel+sudo+suid (hızlı)
make full          # Dağıtım paketi
make dist          # Sürüm + SHA256
```

## Kullanım

### Hızlı başlangıç

```bash
./linuxpi.sh                    # Tüm modüller, metin raporu
./linuxpi.sh --help
./linuxpi.sh --version
```

### Temel seçenekler

```bash
./linuxpi.sh -v                 # Ayrıntılı çıktı
./linuxpi.sh -q                 # Sessiz stderr
./linuxpi.sh --debug
./linuxpi.sh --no-color
```

### Modül seçimi

`kernel`, `sudo`, `suid`, `capabilities`, `cron`, `services`, `containers`, `credentials`, `network`, `security`, `filesystem`, `all` — virgülle birden fazla.

```bash
./linuxpi.sh -m kernel
./linuxpi.sh -m sudo,suid
./linuxpi.sh --full
./linuxpi.sh --minimal
```

### Rapor (`-f`, `-o`)

Yapılandırılmış biçimlerde canlı tarama **stderr**’e gider; rapor **stdout** veya `-o` dosyasına yazılır.

```bash
./linuxpi.sh -f json -o /tmp/scan.json
./linuxpi.sh -f html -o /tmp/report.html -q
./linuxpi.sh -f xml -o /tmp/report.xml
./linuxpi.sh -f markdown -o /tmp/summary.md
```

### Hassas veriler (`--report-full-secrets`)

Yalnızca politika uygunsa; çıktıyı ham sır gibi koruyun.

```bash
./linuxpi.sh --report-full-secrets -f json -o /tmp/out.json
```

### Exploit ve `--run`

```bash
./linuxpi.sh --exploit --risk-level high    # Etkileşimli menü
./linuxpi.sh --run                          # Otomatik kabuk vektörleri (tehlikeli)
# --run: sudo satırları sudo -n ile çalıştırılır; perl gerekir.
# Deneme süresi: AUTO_SHELL_TIMEOUT=900 ./linuxpi.sh --run
```

### Stealth, konteyner, bulut

```bash
./linuxpi.sh --stealth
./linuxpi.sh --container-mode
./linuxpi.sh --cloud aws
```

### Zaman aşımı ve günlük

```bash
./linuxpi.sh --timeout 120
./linuxpi.sh --log-file /var/log/linuxpi.log
```

### Boru ile çalıştırma

```bash
curl -sL https://example.com/linuxpi.sh | bash
curl -sL https://example.com/linuxpi.sh | bash -s -- --minimal -f json
```

## Çıkış kodları

| Kod | Anlam |
|-----|--------|
| `0` | Bulgu yok |
| `2` | CRITICAL bulgular |
| `3` | HIGH bulgular |
| `4` | Diğer bulgular |

## Gereksinimler

- **Bash 4.0+**
- **Temel araçlar**: `find`, `grep`, `awk`, `stat`, `id`
- **İsteğe bağlı**: `jq`, `PyYAML` + `git` (`make update-gtfobins`), `curl`, `shellcheck`

## Geliştirme ve testler

```bash
make check                       # Bash sözdizimi doğrulaması
make test                        # Sözdizimi + unit testler + temel fonksiyonel tarama
make shellcheck                  # Opsiyonel lint; shellcheck yoksa uyarı verir
bash tests/test_exploit_mode.sh
bash tests/test_kernel_matching.sh
```

`make test`, exploit motoru testlerini ve kernel matcher sınır testlerini çalıştırır; ardından `--help` ve sessiz kernel taramasını doğrular.

## Lisans

[Lisans metni (GPL-3.0)](LICENSE) — GNU Genel Kamu Lisansı sürüm 3.

## Güvenlik

LinuxPi’nin kendisindeki güvenlik açıklarını bildirmek için: [SECURITY.md](SECURITY.md).

## Geliştirici

**Cuma KURT** — [cumakurt@gmail.com](mailto:cumakurt@gmail.com)  
[LinkedIn](https://www.linkedin.com/in/cuma-kurt-34414917/) · [GitHub](https://github.com/cumakurt/linuxpi)
