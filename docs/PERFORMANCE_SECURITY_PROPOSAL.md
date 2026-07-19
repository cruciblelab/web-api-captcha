# Maksimum hız + güvenlik önerisi (tartışma için taslak, henüz karar değil)

> Bu dosya bir KARAR değil, bir TARTIŞMA BAŞLANGICI. Hiçbir madde
> uygulanmadı. Kullanıcının isteği: "en iyi modeli varsayılan açalım,
> ama her şey config'lenebilir/değiştirilebilir/kapatılabilir kalsın —
> istese kapatır, sıfırdan yazar, hibrit kullanır." Bu ilke listedeki
> HER maddeye uygulanacak: varsayılan en hızlı+en güvenli kombinasyon,
> ama tek satırla override edilebilir, ve mevcut davranışı hiçbir şey
> kırmıyor (hepsi opt-in/varsayılanlı yeni parametre).
>
> Kaynak disiplini notu: aşağıdaki her madde ya (a) bu konuşmada zaten
> "ekleyelim" dediğimiz ama henüz yapmadığımız gerçek teknik borç, (b)
> kod tabanını okuyup bulduğum somut, doğrulanmış bir verimlilik sorunu,
> ya da (c) gerçek WebSearch ile doğrulanmış, güncel (2025-2026) bir
> teknik/araştırma bulgusu. Hiçbiri hafızadan uydurulmadı; kaynaklar
> madde başlıklarının yanında.

## Bölüm 1 — Bu konuşmada söz verilip henüz yapılmayanlar

### 1.1 TieredStore hızlı katman yazması: fire-and-forget
Az önce (bir sonraki turda) güvenlik için sıralı yazmaya geçtik (yavaş
katman önce, hızlı katman sonra) — doğruydu, ama hızlı katmanın
sonucunu hâlâ `await` ile bekliyoruz, oysa onun başarısız olması zaten
önemsiz (hata yutuluyor). `asyncio.create_task()` ile arka plana atıp
beklemezsek, `trust()`/`bump()`'ın gerçek gecikmesi yaklaşık yarıya
iner. Config: `TieredTrustStore(..., fast_write_mode="background")`
vs `"await"` (varsayılan: background — en hızlısı, güvenlik kaybı yok
çünkü zaten hataları yutuyoruz).

### 1.2 `CachingIPReputationChecker`
Kısa TTL'li (varsayılan ör. 30sn, config edilebilir) bir sarmalayıcı —
aynı IP art arda birden fazla istek attığında (özellikle ücretli bir
itibar API'si kullanılıyorsa) her seferinde yeniden sorgulamak yerine
önbellekten dönsün. `IPReputationChecker` Protocol'üne birebir uyar,
tek satırla `ReputationRiskSignal(CachingIPReputationChecker(gerçek_checker))`
şeklinde sarmalanır — mevcut hiçbir şeyi değiştirmez, opsiyonel katman.

### 1.3 Kısa TTL "son karar" debounce'u (dikkatli ele alınmalı)
Kullanıcının kendi çekincesi doğruydu: bunu statik sayfalara ya da her
isteğe körü körüne uygulamak "sürekli yeniden değerlendirme" özelliğinin
amacına ters düşer. Bunun yerine **sadece PageGuard'ın koruduğu
sayfalarda, çok kısa bir pencerede** (ör. 2-3 saniye, config edilebilir,
varsayılan KAPALI) art arda gelen isteklerde tam risk değerlendirmesini
tekrarlamamak için düşünülebilir — Cloudflare'in "aynı bağlantıdan aynı
saniyede gelen 10 isteğe 10 kere IP itibarı sorma" optimizasyonuna
benzer. `PageGuard(..., recent_verdict_ttl=None)` (varsayılan None =
bugünkü davranış, her istek tam değerlendirilir); `timedelta(seconds=2)`
gibi bir değer verilirse aktif olur.

## Bölüm 2 — 3. taraf captcha API verimliliği (kod okunarak bulunan gerçek sorunlar)

### 2.1 GERÇEK BUG: her `verify()` çağrısı yeni bir httpx.AsyncClient açıp kapatıyor
`webapi_captcha/providers/{recaptcha,hcaptcha,turnstile}.py`'nin her
üçünde de aynı desen doğrulandı:
```python
client = self._external_http_client or httpx.AsyncClient()
try:
    ...
finally:
    if self._external_http_client is None:
        await client.aclose()
```
`http_client=` verilmediği (varsayılan) her durumda, HER `verify()`
çağrısı sıfırdan TCP+TLS handshake yapıp hemen bağlantıyı kapatıyor —
reCAPTCHA/hCaptcha/Turnstile'a yüksek hacimde doğrulama yapan bir site
için gerçek, ölçülebilir gecikme/kaynak israfı. **Düzeltme**: varsayılanı
"her seferinde yeni client" yerine "instance başına bir kez, tembel
(lazy) oluşturulan, tekrar kullanılan client" yap — `provider.aclose()`
metodu ekleyip uygulama kapanışında çağrılmasını dokümante et.
`http_client=` parametresi (dışarıdan kendi client'ını verme) zaten var
ve aynen kalır — bu sadece varsayılan davranışı düzeltiyor, hiçbir
imzayı kırmıyor.

### 2.2 Timeout config edilebilir değil
Üç provider da httpx'in varsayılan 5 saniyelik timeout'una (connect/
read/write/pool hepsi 5sn) sessizce güveniyor — doğruladım
(`httpx.AsyncClient()`'ın gerçek varsayılanı). Yavaş/aksayan bir
üçüncü-taraf API tüm `verify()` çağrısını 5sn boyunca bloke edebilir.
Öneri: `timeout: httpx.Timeout | float | None = None` parametresi
ekle (None = bugünkü httpx varsayılanı, değişiklik yok), site sahibi
isterse `timeout=2.0` gibi daha agresif bir değer verebilsin.

### 2.3 Circuit breaker — bilinen-çökük bir sağlayıcıyı tekrar tekrar deneme
`FallbackCaptchaProvider` zaten `issue()` başarısızlığında bir sonraki
sağlayıcıya geçiyor — ama her ÇAĞRIDA yine başarısız sağlayıcıyı önce
deniyor (timeout'unun dolmasını bekleyerek). Kısa süreli (ör. 30sn,
config edilebilir) bir "bu sağlayıcıyı X saniye atla" hafızası
eklemek, bilinen bir kesinti sırasında her istekte gereksiz timeout
beklemesini önler. Tamamen opsiyonel — `FallbackCaptchaProvider(...,
circuit_breaker_cooldown=None)` (varsayılan None = bugünkü davranış).

### 2.4 Bağlantı havuzu limitleri config edilebilir değil
`httpx.AsyncClient()`'ın varsayılan `max_connections=100`,
`max_keepalive_connections=20` değerleri doğrulandı — çok yüksek
trafikli bir dağıtımda bu sayılar dar gelebilir ya da fazla gelebilir
(bellek). 2.1'deki kalıcı client'a `limits: httpx.Limits | None`
parametresi eklemek, ihtiyaç halinde ayarlanabilir kılar.

## Bölüm 3 — Sıfırdan, gerçekten yeni fikirler (araştırmayla desteklenmiş)

### 3.1 JA4 TLS parmak izi sinyali
[JA4](https://cory.so/ja4-passive-tls-fingerprinting), JA3'ün yerini
alan, 2025-2026'da Auth0 gibi gerçek şirketlerin bot tespitinde
kullandığı ([Auth0 blog](https://auth0.com/blog/strengthening-bot-detection-ja4-signals/))
güncel bir teknik — TLS handshake'in kendisi (User-Agent'ten farklı
olarak, JS ile taklit edilmesi çok daha zor bir katman) bir bot/scraper
imzası bırakıyor. **Önemli kısıt, dürüstçe belirtilmeli**: TLS
sonlandırma genelde bir reverse proxy'de (nginx, Cloudflare, ALB)
oluyor — çıplak bir FastAPI/Uvicorn süreci JA4'ü kendi başına GÖREMEZ.
Bu yüzden bu ancak reverse proxy'nin fingerprint'i bir header'a
(`X-JA4` gibi) enjekte ettiği kurulumlarda işe yarar (Cloudflare zaten
bunu yapıyor). Tasarım: `JA4RiskSignal` — paketin geri kalanıyla aynı
felsefe, kendi kendine header okumuyor, `ctx.signals["ja4"]`'ten (ya da
ayrı bir `RiskContext` alanından) okuyor, bilinen-şüpheli parmak izi
listesine karşı kontrol ediyor. Küçük, güvenli, ama sadece belirli
dağıtım topolojilerinde anlamlı — dokümantasyonda bu kısıt net
yazılmalı.

### 3.2 WebAuthn tabanlı cihaz güveni — TrustStore'un çerezden daha güçlü alternatifi
Gerçek, aktif bakımlı bir Python kütüphanesi var:
[`webauthn`/py_webauthn](https://pypi.org/project/webauthn/) —
Production/Stable durumda, WebAuthn Working Group'ta yer alan biri
tarafından bakımı yapılıyor, 2025-2026 boyunca düzenli sürüm almış.
(Privacy Pass turunda "olgun kütüphane yok" dediğimiz durumdan FARKLI —
burada gerçekten var, bu yüzden bu fikri güvenle önerebiliyorum.)
Fikir: ilk başarılı captcha çözümünde, isteğe bağlı olarak bir WebAuthn
platform authenticator kaydı da tetiklenir (Face ID/Touch ID/Windows
Hello — biyometrik veri cihazdan asla çıkmaz, sadece imzalı bir
challenge). Sonraki ziyaretlerde çerez yerine (ya da onunla birlikte)
bir WebAuthn assertion'ı doğrulanır — donanım destekli, phishing-
resistant, "çerezleri temizle"yle kaybolmuyor, çalıntı bir session
cookie'den çok daha güçlü. `WebAuthnTrustStore` olarak `TrustStore`
Protocol'üne uyan, `webauthn` extra'sı arkasında yeni bir modül olabilir
— tamamen opsiyonel, mevcut çerez tabanlı `TrustStore`'un yerini almaz,
yanında bir seçenek olur. **Gerçek frontend JS işi gerektiriyor**
(widget/beacon'a WebAuthn `navigator.credentials.create/get` çağrıları
eklenmeli) — küçük bir iş değil, ayrı bir tur gerektirir.

### 3.3 Apple/Cloudflare Private Access Token DOĞRULAYICISI (en heyecan verici, en çok araştırma gerektiren)
[Private Access Tokens](https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/)
(Privacy Pass'in gerçek, canlı bir uygulaması) 2022'den beri
prodüksiyonda — Cloudflare zaten issuer, Safari/iOS 16+/macOS Ventura+
varsayılan destekliyor, Edge kısmi destek, Chrome flag arkasında
geliştiriliyor. Gerçek prodüksiyon verisi: Apple-ağırlıklı trafikte
**%8-14 dönüşüm artışı** (CAPTCHA sürtünmesi azaldığı için).

Geçen tur "kendi blind-signature issuer'ımızı yazmayalım" dedik (doğru
karardı — issuer olmak riskli). Ama burada **issuer OLMAYA çalışmıyoruz**
— Apple/Cloudflare/Fastly zaten bunu işletiyor. Biz sadece zaten ihraç
edilmiş token'ları DOĞRULAYAN taraf olabiliriz. Kritik teknik ayrım
(mutlaka doğrulanmalı, ama umut verici): RFC 9474'ün son doğrulama
adımı standart bir RSA-PSS imza kontrolü — "blind" kısmı sadece ihraç
sürecine özgü, doğrulama tarafı normal RSA-PSS, ki `cryptography`
paketi bunu ZATEN destekliyor. Yani ihraç edemesek de, doğrulayabilme
ihtimalimiz var, hiç blind-signature kodu yazmadan.

**Bu madde "hemen yapılabilir" değil** — RFC 9578'in tam HTTP challenge/
response formatı (`WWW-Authenticate: PrivateToken`,
`Sec-Private-Access-Token` header'ları), issuer public key/JWKS
yayınlama detayları ayrı, derinlemesine bir araştırma turu gerektiriyor.
Ama başarırsak: hiçbir kod yazmadan, sadece bir HTTP header doğrulayarak,
Safari/Apple kullanıcılarının büyük kısmına captcha göstermeden
geçirebiliriz — bu şu an açık kaynak hiçbir captcha kütüphanesinde yok.

### 3.4 Singleflight / uçuş-içi tekilleştirme
Aynı IP için eşzamanlı birden fazla `assess_risk()` çağrısı varsa (bir
sayfa aynı anda birkaç kaynak isteği tetiklerse), aynı itibar
sorgusunu N kere paralel tekrarlamak yerine tek "uçuşa" indirmek —
kod tabanında zaten AYNI DESEN var (`AdaptiveCaptchaGate._token_locks`,
anahtar başına `asyncio.Lock`), yani yabancı bir kavram değil, tutarlı
bir uzantı. `CachingIPReputationChecker`'a (3.1) doğal bir ek olur:
önbellek miss'inde aynı IP için eşzamanlı ikinci bir sorgu, ilkinin
sonucunu bekler, ikinci kez ağa gitmez.

## Bölüm 4 — Küçük/orta performans iyileştirmeleri

### 4.1 `orjson` (opsiyonel)
`receipts.py`'nin kanonik JSON'ı (imza için deterministik serialize
gerekiyor, `orjson.OPT_SORT_KEYS` bunu native destekliyor) ve
`redis_store.py`'nin serialize/deserialize'ı için stdlib `json`'dan
belirgin şekilde hızlı. Opsiyonel extra (`webapi-captcha[fast]` gibi),
yoksa stdlib `json`'a sessizce düş — hiçbir zorunlu yeni bağımlılık
değil.

### 4.2 `uvloop` notu (kod değişikliği değil, dokümantasyon)
Kütüphanenin kendisi event loop politikası dayatmıyor (doğru, dayatmamalı)
— ama README'ye "production'da `uvloop` kullanmayı düşünün" gibi bir
performans notu eklemek, tüketici uygulamanın kendi kararı olarak
kalır.

### 4.3 SQL store index/sorgu gözden geçirmesi
Hızlı bir tarama önerilir (muhtemelen zaten iyi durumda — PK bazlı
lookup'lar indeksli) ama resmi bir audit yapılmadı, bir sonraki turda
kısa bir kontrol geçirilebilir.

## Bölüm 5 — "En iyi varsayılan model" preset'i

Kullanıcının asıl isteği: yukarıdakilerin HEPSİ tek tek config edilebilir
kalsın, ama bir yerde "en hızlı + en güvenli" kombinasyonu **varsayılan
açık** olarak tek çağrıyla sunulsun. `presets.py`'deki mevcut
`build_cloudflare_style_guard()` bunun doğal genişleme noktası:
- `RiskEngine` + `CorroboratedRiskSignal([ReputationRiskSignal(...),
  BehaviorScoreRiskSignal()])` (tek sinyalin tek başına karar
  vermemesi) varsayılan açık.
- `ReplayRiskSignal` (aynı store `RepeatedMovementCheck`'e de
  bağlanır) varsayılan açık.
- `CachingIPReputationChecker` (4.1'deki) varsayılan açık (kısa TTL).
- `trusted_revalidation` varsayılan açık (hafif bir kontrol).
- Redis mevcutsa `TieredTrustStore`/`TieredRunningRiskStore` otomatik
  kurulur, yoksa düz `Memory`/`SQL`'e düşer.
- Her parça ayrı ayrı `None`/`False` verilerek kapatılabilir, ya da
  hiç bu preset'i kullanmayıp sıfırdan/hibrit kurulabilir — bugünkü
  "kullanmak zorunda değilsin" ilkesi korunur.

## Öncelik sıralaması önerim (tartışma için)

1. **2.1 (httpx client reuse)** — en yüksek etki, en düşük risk, gerçek
   bir bug, hemen yapılabilir.
2. **1.1 (fire-and-forget fast tier)** — düşük risk, doğrudan gecikme
   kazancı, hemen yapılabilir.
3. **1.2 (CachingIPReputationChecker)** + **3.4 (singleflight)** —
   birlikte tasarlanırsa en çok kaynak tasarrufu sağlayan ikili.
4. **2.2/2.3/2.4 (timeout/circuit-breaker/pool config)** — orta
   öncelik, dayanıklılık odaklı.
5. **Bölüm 5 (preset)** — üsttekiler bitince, hepsini tek çağrıda
   toplayan son adım.
6. **3.1 (JA4)**, **3.2 (WebAuthn)** — gerçek ve değerli ama her biri
   kendi başına ayrı bir tur (JA4 küçük ama dağıtıma bağımlı; WebAuthn
   frontend işi gerektiriyor).
7. **3.3 (PAT doğrulayıcı)** — en yüksek potansiyel etki ama önce ayrı,
   derinlemesine bir protokol araştırması gerektiriyor, "hemen
   uygulama" listesine henüz giremez.
