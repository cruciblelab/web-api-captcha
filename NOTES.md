# Geliştirici Notları (oturumlar arası kalıcı hafıza)

> Bu dosya, discord-webapi'de zaten kullanılan desenin aynısı:
> harici/git-tracked olmayan plan dosyaları oturumlar arası kaybolabiliyor
> ya da bulması zorlaşıyor, bu yüzden kalıcı mimari kararlar burada
> (repo'nun kendi içinde, git ile push edilerek) tutuluyor.
> `CHANGELOG.md` neyin değiştiğini, bu dosya NEDEN öyle tasarlandığını
> anlatıyor.

## Fiziksel test gerektirmeyen iki iş: trust receipt binding + test hijyeni (7. tur)

Kullanıcı sonnet-5'e geri dönüp "fiziksel teste kadar ne yapabiliriz"
diye sordu. Önceki güvenlik taramasında bulduğum ama o zaman "kapsam
dışı, dokümante edilmiş bir sınır" dediğim iki maddeyi somutlaştırdım —
ikisi de tamamen backend, sıfır fiziksel test yükü:

1. **`TrustTokenVerifier.verify(token, *, expected_subject_id=None,
   required_purpose=None)`** — artık isteğe bağlı olarak receipt'in
   `subject_id`/`purpose`'ını doğrulayabiliyor, uyuşmazlıkta `None`
   dönüyor (aynı fail-closed disiplini). `AdaptiveCaptchaGate.
   is_currently_trusted()`/`get_info()`/`verify()` ve `PageGuard.
   require_human()`'a aynı iki opsiyonel parametre olarak taşındı.
   Varsayılan (ikisi de None) davranış birebir aynı — çağıran hâlâ
   isterse hiç binding yapmadan kullanabilir.
2. **SQL test fixture'ı artık `engine.dispose()` çağırıyor** — tam
   suite'te aralıklı görülen `PytestUnhandledThreadExceptionWarning`
   gürültüsünün kaynağıydı (aiosqlite'in arka plan thread'i, pytest bir
   sonraki testin event loop'unu kapattıktan sonra hâlâ eski loop'a
   sinyal göndermeye çalışıyordu). 3 kere art arda tam suite çalıştırılıp
   uyarının tamamen kaybolduğu doğrulandı.

Preset (`build_cloudflare_style_guard`) kontrol edildi, değişiklik
gerekmedi — zaten `reputation=None` geçilse bile gate'e her zaman
gerçek (boş) bir `StaticBlocklistReputationChecker()` veriyor, yeni
"reputation VEYA risk_engine zorunlu" kuralına zaten uyumlu.

359 test yeşil (350 → 359), ruff/mypy temiz, 3 art arda tam suite
çalıştırmasında uyarı sayısı stabil (1, önceden var olan httpx
deprecation notu — bizim değişikliğimizle ilgisiz).

### Ek: `widget.js` XSS düzeltmesi de (aynı tur, kullanıcı "başka bir şey var mı" diye sorunca)

Güvenlik taramasındaki son açık kalem de kapatıldı:
`renderImageChallenge()`, `challenge.image_data_uri`'yi `innerHTML`
string'ine concat ediyordu — yerleşik provider'larda güvenli (sunucu
üretimi base64 data URI) ama custom bir `CaptchaProvider` saldırgan-
etkili veri koyarsa gerçek XSS. Görsel çıktıyı DEĞİŞTİRMEDEN
(`document.createElement('img')` + `.src` PROPERTY ataması — `.src`'ye
atama hiçbir zaman markup olarak parse edilmiyor, `innerHTML`'in
aksine) düzeltildi. Frontend dosyası ama tek satırlık/mekanik bir
değişiklik olduğu için (görünen davranış birebir aynı) fiziksel test
turu beklemeden yapıldı — `node --check` ile sözdizimi doğrulandı,
otomatik bir regresyon testi eklendi (`<img src="` artık script
metninde YOK, `img.src = challenge.image_data_uri` VAR). Bir sonraki
fiziksel test turunda gözle bir kez teyit edilmesi yeterli, ayrı bir
tur gerekmiyor. 360 test yeşil.

## Performans/verimlilik araştırması + kapsamlı öneri listesi (5. tur)

Kullanıcı "eş zamanlı worker/kuyruk sistemi ekleyelim mi" diye sordu;
konuşurken kendisi de fark etti ki captcha doğası gereği senkron
istek-cevap, kuyruğa almak anlamsız — bunun yerine "mevcut hâli maksimum
verimli hale getirelim, çok kaynak tüketiyor, insanlar kullanmazsa
anlamı yok" diye yön değiştirdi. Bu isteğe gerçek araştırma (WebSearch,
kod okuma) ile karşılık verildi; tam liste **`docs/PERFORMANCE_SECURITY_
PROPOSAL.md`** dosyasında — bu not sadece özet/karar kaydı, ayrıntı
için o dosyaya bakın.

**Kod okuyarak bulunan gerçek bug**: `providers/{recaptcha,hcaptcha,
turnstile}.py`'nin üçü de her `verify()` çağrısında `http_client=`
verilmediği sürece sıfırdan bir `httpx.AsyncClient()` açıp hemen
kapatıyor — her doğrulamada TCP+TLS handshake'i baştan yapıyor. Bu,
muhtemelen "aşırı kaynak tüketimi" hissinin gerçek kaynağı, en yüksek
etki/en düşük riskli düzeltme. **Bu turda SADECE bu düzeltiliyor**
(aşağıya bakın) — kullanıcının kararı: "aşırı kapsamlı vermeyelim,
şu an overengineering olur, kimse kullanmaya başlamadan testler aşırı
zorlaşır, küçük bir kısmını ekleyelim, bu bug'ı kapatmak yeterli."

**Araştırmayla bulunan, ama BİLEREK ERTELENEN üç fikir** (ayrı, kendi
başlarına derinlemesine tur gerektiriyor, şimdi kod yazılmadı):
1. **JA4 TLS parmak izi sinyali** — gerçek, güncel (Auth0 kullanıyor)
   ama sadece reverse-proxy fingerprint'i header'a enjekte ederse
   anlamlı (çıplak Uvicorn/FastAPI TLS'i göremez).
2. **WebAuthn tabanlı cihaz güveni** — gerçek, olgun bir Python
   kütüphanesi VAR (`webauthn`/py_webauthn, Production/Stable) — ama
   gerçek frontend JS işi gerektiriyor, ayrı bir tur.
3. **Apple/Cloudflare Private Access Token DOĞRULAYICISI** (issuer
   değil!) — en heyecan verici fikir: PAT zaten canlı, Cloudflare 2022'den
   beri issuer, gerçek prodüksiyon verisi (Apple-ağırlıklı trafikte
   %8-14 dönüşüm artışı). Doğrulama adımı teorik olarak standart
   RSA-PSS (blind kısmı sadece ihraçta), yani `cryptography` ile
   YAPILABİLİR olabilir — ama RFC 9578'in tam HTTP header/JWKS
   protokolü netleşmeden kod yazılmayacak, ayrı bir araştırma turu.

Diğer küçük/orta öneriler (fire-and-forget tiered yazma,
CachingIPReputationChecker, singleflight, timeout/circuit-breaker
config'leri, orjson, "en iyi varsayılan" preset) hepsi dosyada
listeli, hiçbiri bu turda yapılmadı — bilinçli olarak.

## Kompozisyon esnekliği: reputation opsiyonel + ConditionalRiskSignal (6. tur)

Kullanıcının isteği (fable-5'e geçtikten sonra): "tam config edilebilir,
bizim verdiklerimiz istediği sıra, IP itibarı şüpheliyse başka şeyler
tetikleme gibi kendi zincirlerini kurabilsinler, IP itibarı sistemini
tamamen çıkartabilsinler." Önce kodu gösterip neyin zaten mümkün olduğunu
(SignalScoreCheck kendi heuristic'leri, RiskEngine sıralı liste + add/
remove/get_signal + enabled toggle) neyin gerçekten eksik olduğunu
ayırdım. İki gerçek eksik yapıldı:

1. **`AdaptiveCaptchaGate.reputation` artık opsiyonel.** Eskiden 3.
   positional zorunlu argümandı — RiskEngine kullansan bile boşuna bir
   IP itibarı nesnesi vermek zorundaydın ("IP itibarını çıkartamıyorum"
   şikayetinin tam kaynağı). Artık `reputation=None` + `risk_engine=...`
   ile IP itibarı yolu tamamen düşürülebiliyor. `decision_store` ve
   `escalation_provider` de opsiyonel yapıldı (decision_store yoksa
   `MemoryAdaptiveDecisionStore` otomatik; escalation gerekip de provider
   yoksa `AttributeError` yerine net `ValueError`). İkisi de (reputation
   VE risk_engine) None ise construction'da `ValueError` — o kombinasyon
   asla escalate edemezdi. Mevcut positional çağrılar hiç kırılmadı
   (default'lar eklendi, positional geçenler değerlerini override ediyor).

2. **`ConditionalRiskSignal(when=A, then=B)`** — B'yi sadece A "flag"
   ederse çalıştırır. "IP itibarı şüpheliyse başka şeyleri tetikle"nin
   genel hali: A ve B herhangi iki sinyal, IP itibarına bağlı değil,
   zincirlenebilir (`A → B → C`). RiskEngine'in kendi sıralaması/
   short_circuit'i bunu ifade EDEMİYORDU (onlar her sinyali harmanlıyor;
   bu, takip sinyalinin çağrısını komple atlıyor) — pahalı/ücretli/yavaş
   bir kontrolü ucuz bir kontrolün arkasına saklamak için. `when`/`then`
   flag testi `CorroboratedRiskSignal` ile ortak `_signal_flags()`
   yardımcısına çıkarıldı.

350 test yeşil (338 → 350), ruff/mypy temiz.

### Kullanıcının onayıyla ERTELENEN, "önerin çok kıymetli, notlarına ekle" denen widget işleri

Kullanıcı bunları beğendi ama şimdi yapmadık, sonraki turlara kaldı
(overengineering yapmamak için, kullanıcının önceki turlardaki disiplin
isteğiyle tutarlı):

- **Hazır widget görünümleri/temaları** — şu an `widget.js`'in TEK sabit
  görünümü var (Cloudflare-Turnstile tarzı checkbox). 2-3 hazır tema
  (light/dark/minimal/pill gibi) + `data-theme`/renk/etiket config'i
  eklenecek. Kullanıcının "hazır widget görünümleri" isteğinin karşılığı.
- **Genişletilebilir renderer sistemi** — yeni bir challenge türünün
  frontend render'ını `widget.js`'i çatallamadan kaydedebilmek için bir
  "renderer registry" (`window.wacRegisterChallengeRenderer(kind, fn)`
  gibi). Şu an render mantığı içeride sabit bir `switch`.
- **`image_data_uri` innerHTML XSS tuzağı** (geçen turun güvenlik
  taramasında bulundu) — `widget.js:253` `image_data_uri`'yi kaçışsız
  innerHTML'e gömüyor. Yerleşik provider'larda güvenli (sunucu-üretimi
  base64 data URI), ama custom provider bu alana saldırgan-etkili veri
  koyarsa XSS. Renderer refactor'ı sırasında img'yi `createElement`+`.src`
  ile kurarak kapatılacak. Düşük şiddet, canlı açık değil.
- **Trust receipt `subject_id` binding'i** (aynı taramadan) — opsiyonel
  `expected_subject_id`/`required_purpose` doğrulaması, bir gün.

## Dayanıklılık düzeltmesi + "güvenilir" artık koşulsuz bypass değil (4. netleştirme turu)

Kullanıcının iki somut isteği: (1) kesinti/çökmede veri kaybı/yazma
sorunu olmamalı, ("direkt silmek mantıklı" onayı + konfigürasyon
isteği), (2) ziyaretçi "güvenilir" olsa bile (trust_store ya da receipt
üzerinden) config ile ek bir kontrolü (ör. IP itibarı) hâlâ çalıştırıp,
o kontrol bir şey yakalarsa güveni geçersiz kılabilme. "İyice düşün, ölç
tart, araştırma yap, karar ver" dendiği için gerçek bir deneyle
doğrulayıp karar verdim.

**Gerçek bug, deneyle bulundu**: `TieredTrustStore`/`TieredRunningRiskStore`
`asyncio.gather()` ile iki katmana PARALEL yazıyordu. Python REPL'de
gerçek bir deneyle doğruladım: `gather()` iki coroutine'den biri patlarsa
HEMEN o exception'ı fırlatıyor, ama diğer coroutine arka planda çalışmaya
devam ediyor — eğer o da patlarsa, bu İKİNCİ (ve genelde daha önemli)
hata **sessizce yutuluyor**, çağıran taraf hiç haberdar olmuyor. Yani
yavaş/kalıcı katman (SQL) da aynı anda başarısız olsaydı, bunu asla
öğrenemezdik. **Düzeltme**: artık sırayla yazıyor — önce YAVAŞ/kalıcı
katman (gerçek veri kaynağı, hata fırlatırsa HER ZAMAN yukarı taşınır),
sonra hızlı katman (Redis gibi — sadece cache, hata fırlatırsa YUTULUR,
işlemi çökertmez). Okuma tarafında da aynı mantık: hızlı katman
patlarsa (Redis kesintisi), yavaş katmana düş — kesinti performansı
düşürsün, doğruluğu bozmasın. Yeni `on_fast_tier_error` callback'i bu
yutulan hataları gözlemlemek için (loglama/metrik).

**"Güvenilir" artık koşulsuz değil**: `AdaptiveCaptchaGate`'e yeni
opsiyonel `trusted_revalidation: RiskSignal | None` +
`trusted_revalidation_threshold: float = 0.5`. `is_currently_trusted()`
artık: trust_store/receipt'ten biri "güvenilir" dese bile, bu sinyal
konfigüreliyse hâlâ çalıştırılıyor; `hard_override` ya da eşiği aşan
`suspicion` varsa, o çağrı için güven GEÇERSİZ sayılıyor (normal risk
akışına düşülüyor). Paketin geri kalanının fail-open felsefesiyle tutarlı
— bu kontrolde bir exception olursa güven İPTAL EDİLMİYOR (receipt
`verify()`'ın fail-closed olmasından FARKLI, çünkü bu ek bir kontrol,
güveni VEREN şey değil). `trusted_revalidation=None` (varsayılan)
bugünkü "güvenilirse tamamen atla" davranışını birebir koruyor.

Tamamen ek/opt-in, 333 test yeşil (322 → 333), ruff/mypy temiz.

## Tiered storage + v1 siteler-arası güven receipt'i (3. netleştirme turu)

Kullanıcının isteği: "hatırlama" (TrustStore/RunningRiskStore) sistemi
için performans amaçlı katmanlı önbellekleme (örneği: 6 saate kadar
Redis, sonrası başka bir depo) ve daha önceki "bir sitede doğrulanan
başka sitede de tanınsın" vizyonunun somut, güvenli bir ilk sürümü.

**Önce dürüst bir araştırma yapıldı** (WebSearch ile doğrulanmış):
IETF'in Privacy Pass standardı gerçek (RFC 9576/9577/9578, Haziran 2024,
RSA Blind Signatures RFC 9474 üzerine kurulu) ama Python'da bunu
uygulayan olgun/denetlenmiş bir kütüphane BULUNAMADI. Kendi
blind-signature kriptografimizi bir oturumda, uzman denetimi olmadan
yazmak "maksimum güvenlik" hedefiyle çelişirdi — bu yüzden kademeli bir
yol izlendi: **v1'i şimdi, sadece zaten denetlenmiş primitiflerle
(`cryptography` paketi) inşa et; gerçek anonim blind-signature'ı ("v2")
ileride, denetlenmiş bir kütüphane çıkarsa ele al.**

### 1) `TieredTrustStore`/`TieredRunningRiskStore` (`webapi_captcha/tiered.py`)

Cache-aside: yaz → hem hızlı hem yavaş katmana (hızlı katmanın TTL'i
`fast_ttl_cap`'e sıkıştırılır, kendi kendine siliniyor); oku → önce
hızlı, miss'te yavaş katmana düş. **Kritik incelik** (Plan agent'ının
bulup testle doğruladığı): `TieredRunningRiskStore.bump()` iki katmana
olduğu gibi yazamaz — önce `get()` (hızlı→yavaş fallback) ile gerçek
mevcut seviyeyi okuyup `max(current, yeni)` alması, SONRA bu birleşmiş
değeri her iki katmana yazması gerekiyor; yoksa hızlı katmanın süresi
dolduktan hemen sonra gelen düşük bir bump, yavaş katmandaki hâlâ geçerli
yüksek seviyeyi sessizce geçersiz kılabilirdi. Testle (`test_tiered_
running_risk_store_bump_merges_across_tiers_never_regresses`) doğrulandı.
Gerçek bir Redis backend'i de eklendi (`webapi_captcha/redis_store.py`,
yeni `redis` extra'sı arkasında, `all`'a EKLENMEDİ çünkü `all` bugün
"canlı dış servis gerekmez" anlamına geliyor). **Test sırasında bulunan
gerçek bug**: Redis'in `SET ... EX ...`'i negatif/sıfır TTL'i hata olarak
reddediyor (Memory store'ların "zaten geçmişte" davranışının aksine) —
`_expire_seconds()` yardımcı fonksiyonuyla düzeltildi (negatif/sıfır TTL
→ anahtarı sil, SET'e hiç gitme).

### 2) v1 siteler-arası güven receipt'i (`webapi_captcha/receipts.py`)

**Fernet değil, Ed25519** — Fernet simetrik olduğu için güven ağındaki
her site aynı gizli anahtarı paylaşmak zorunda kalırdı (anahtarı bilen
herkes sahte receipt basabilirdi). Ed25519 ile issuer private key'le
imzalar, verifier'lar sadece public key tutar — imzalayamaz, sadece
doğrulayabilir. Bir verifier birden fazla issuer'a güvenebilir
(`dict[issuer_id, public_key]`).

- `TrustReceipt.subject_id` **ANONİM DEĞİL** — aynı subject_id iki farklı
  sitede sunulursa eşleştirilebilir; bu gerçek Privacy Pass'in önlediği
  şey, burada çözülmüyor, dokümantasyonda açıkça yazılı.
- `TrustTokenVerifier.verify()` **BİLEREK FAIL-CLOSED** — paketin geri
  kalanının fail-open felsefesinden bilinçli bir sapma: bir receipt
  güveni doğrudan veren şey, o yüzden herhangi bir belirsizlik her zaman
  `None` döner.
- **Entegrasyon**: `RiskSignal` DEĞİL (RiskEngine sadece yükseltmek için
  tasarlı, aşağı zorlama mekanizması yok) — `TrustStore` ile PARALEL,
  ikinci bir "zaten güvenilir" kaynağı. `AdaptiveCaptchaGate.__init__`'e
  opsiyonel `trust_token_verifier=`, `is_currently_trusted()`/
  `get_info()`/`verify()`'a opsiyonel `trust_token=` — mantık: receipt
  geçerli VEYA trust_store güveniyor → güvenilir (OR). `PageGuard.
  require_human()` de aynı şekilde — **bu paket `request.headers`/
  `cookies`'e kendisi bakmıyor**, çağıran uygulama token'ı çıkarıp elle
  geçiriyor.
- **Bilerek çözülmeyen**: `subject_id`'nin yerel `user_id` ile eşleştiği
  doğrulanmıyor (çağıran uygulamanın sorumluluğu) ve token'ın site A'dan
  site B'ye tarayıcı üzerinden nasıl taşınacağı (üçüncü-taraf çerezler
  kaldırılıyor, bu ayrı ve çözülmemiş bir dağıtım problemi).

Tamamen ek/opt-in: `TrustStore`/`RunningRiskStore` Protocol şekli
değişmedi, `AdaptiveCaptchaGate`'in mevcut hiçbir constructor parametresi
kırılmadı. 322 test yeşil (300 → 322), ruff/mypy temiz.

## PyPI yayını öncesi captcha-ekosistemi araştırması ve `LoadAdaptiveDifficulty`

PyPI'ye yayınlamadan önce açık-kaynak captcha/anti-bot ekosistemi
(hCaptcha, ALTCHA, Cap.js, mCaptcha, FriendlyCaptcha, reCAPTCHA v3,
Cloudflare Turnstile) gerçek WebSearch/WebFetch ile araştırıldı (hayal
ürünü değil). İki somut, kaynaklı bulgu:

1. **Erişilebilirlik**: WebAIM anketine göre CAPTCHA, ekran-okuyucu
   kullanıcıları tarafından en çok şikayet edilen erişilebilirlik
   engeli. ALTCHA/Cap.js, görsel/işitsel challenge gerektirmeyen
   PoW/instrumentation yaklaşımlarını tam bu yüzden pazarlıyor. Bizim
   `ProofOfWorkProvider`/`SignalScoreCheck`/`RepeatedMovementCheck`/
   `PathTraceProvider` zaten görsel challenge gerektirmiyor ama bu hiç
   dokümante edilmemişti — README'ye bir "Accessibility" bölümü eklendi.
2. **Yük-adaptif PoW zorluğu**: mCaptcha'nın öne çıkan özelliği, sunucu
   yüküne göre PoW zorluğunu otomatik ölçeklendirmesi (DDoS/trafik
   artışında zorlaşır, normal trafikte ucuz kalır). Bizim
   `ProofOfWorkProvider.difficulty` sabitti — **`LoadAdaptiveDifficulty`**
   eklendi (`providers/proof_of_work.py`): sliding-window bir callable,
   `difficulty=` parametresine `int` yerine geçirilebiliyor.

## `RiskEngine` — çok sinyalli, kademeli captcha tetikleme kararı

Kullanıcının isteği: reCAPTCHA/hCaptcha gibi harici sistemleri (ya da
kendi sağlayıcılarımızı) her seferinde direkt çağırmak yerine, önce
ücretsiz/kendi sinyallerimizle "gerçekten şüpheli mi?" sorusunu sorup
sadece gerekince asıl captcha'yı tetikleyen bir ön-karar katmanı. Üç ek
netleştirme: (1) karar sadece IP itibarına dayanmamalı, belirli
rotalar/purpose'lar için ek taban seviye tanımlanabilmeli, (2) arka
planda toplanan sinyaller ziyaretçi bir sayfaya girdikten SONRA da
tetikleyebilmeli, (3) IP itibarı berbatsa direkt en üst kademeye
atlanmalı.

Yeni modül **`webapi_captcha/risk.py`**:
- `RiskLevel(IntEnum)`: `MINIMAL < LOW < ELEVATED < HIGH`.
- `RiskSignal` Protocol (`name`, `weight`, `async def assess(ctx) ->
  RiskContribution`) — `RiskContribution.suspicion` **bilerek**
  `SignalScoreCheck`'in tam tersi kutupta (1.0=şüpheli, orada
  1.0=insan-gibi) — `RiskLevel`'in kendi sıralamasıyla tutarlı kalsın
  diye.
- `RiskEngine`: sinyalleri ağırlıklı ortalamaya çevirip
  `level_thresholds`'a göre `RiskLevel`'e eşliyor; herhangi bir
  `hard_override` (en yükseği kazanır) eşiklerin önüne geçiyor. Her
  sinyal kendi try/except'i içinde (`fail open`).
- `ReputationRiskSignal`/`BehaviorScoreRiskSignal`: mevcut
  `IPReputationChecker`/`SignalScoreCheck`'i sarmalıyor.
- `RunningRiskStore` (Memory/SQL): bir ziyaretçinin oturum boyunca
  BİRİKEN risk seviyesi — `bump()` tek yönlü, sadece yükseltir.
- `AdaptiveCaptchaGate.assess_risk()`: hem `PageGuard.require_human()`
  hem `verify()`'ın aynı yerden geçtiği tek karar noktası;
  `min_level_by_purpose`, `running_risk_store`, `escalation_providers`
  (kademe başına farklı `CaptchaProvider`) hepsi buradan uygulanıyor.
  `risk_engine=None` her zaman eski davranışı birebir koruyor.
- `build_passive_risk_router()` (`pageguard.py`): frontend periyodik
  sinyal POST'lar, `RunningRiskStore`'a `bump()` eder — sonraki her
  `PageGuard` kontrolü bunu otomatik görür, ayrıca bir "cache geçersiz
  kılma" mekanizması gerekmedi çünkü `PageGuard` zaten her istekte
  sıfırdan karar veriyor.

## İkinci netleştirme turu — kullanıcı "hepsi ayarlanabilir/genişletilebilir olsun" dedi

Somut dört istek: (1) arka plan sinyalleri basitçe aç/kapa edilebilsin,
(2) IP itibarı tek başına değil, başka bir sinyalle birlikte "aynı fikirde
olma" şartı konabilsin, (3) replay/tekrar-tespiti (`replay_guard.py`)
hem RiskEngine'e bağlansın hem esnekleşsin, (4) captcha widget'ine (aslında
pasif risk endpoint'ine) sinyal gönderecek bir frontend eksikti.

- **`enabled` aç/kapa**: `RiskSignal` Protocol'üne EKLENMEDİ (üçüncü-taraf
  sinyalleri kırmasın diye) — `RiskEngine.assess()` `getattr(signal,
  "enabled", True)` kontrolü yapıyor. Her sinyal `enabled: bool = True`
  constructor parametresi aldı.
- **`CorroboratedRiskSignal`**: 2+ alt sinyalin bağımsız olarak "aynı
  fikirde" olmasını şart koşuyor (`min_agreements=None` → hepsi, yoksa
  k-of-n). **Kritik bir tasarım hatası test sırasında bulunup düzeltildi**:
  ateşlenmediğinde kendi `suspicion`'ı ilk halde alt sinyallerin ham
  ortalamasıydı — ama tek bir aktif (abstain olmayan) çocuk varsa
  (mesela IP itibarı flag'ledi, davranış sinyali henüz veri toplamadığı
  için abstain etti), ortalama tek değere indirgeniyor ve o değer zaten
  1.0 olabiliyordu — yani corroboration'ı BOYPASS EDEREK RiskEngine'in
  kendi HIGH eşiğini tek başına aşabiliyordu, tam da bu sınıfın önlemesi
  gereken şeyi bir seviye geriden yeniden üretiyordu. Düzeltme: ateşlenmediğinde
  `suspicion = flagged / active` (anlaşma ORANI, ham ortalama değil) —
  bu formül matematiksel olarak `required/active`'in altında kalmaya
  MECBUR (çünkü bu dal sadece `flagged < required` iken çalışıyor), yani
  tek başına asla tam-anlaşmayla aynı güvene ulaşamıyor.
- **`ReplayRiskSignal`**: mevcut replay-tespiti (`RepeatedMovementCheck`/
  `TrajectoryFingerprintStore`) RiskEngine'e bağlandı. **Kasıtlı olarak
  salt-okunur** — `store.record()` ASLA çağırmıyor, sadece
  `seen_recently()` okuyor. Gerekçe: `assess_risk()` gerçek bir
  `verify()`'dan çok daha sık çalışıyor (her `PageGuard.require_human()`,
  her widget `get_info()`); eğer `assess()` da kaydetseydi, hiç gerçek
  doğrulamaya varmayan bir sayfa-yüklemesi bile bir parmak izini
  "kullanılmış" olarak yakardı. Kayıt sadece `RepeatedMovementCheck.run()`'da
  kalıyor — ikisini de AYNI store'a karşı bağlamak gerekiyor, aksi halde
  `ReplayRiskSignal` hiçbir şey yakalayamaz (docstring'de açıkça yazılı).
  `replay_guard.py`'nin ızgara sabitleri (`_GRID_PX` vb.) `DEFAULT_*`
  public isimlere çevrilip `fingerprint_trajectory()`/
  `RepeatedMovementCheck`'e keyword parametre olarak eklendi.
- **`webapi_captcha/beacon.py` + `beacon.js`** (yeni dosya çifti,
  `widget.py`'ye DEĞİL): `PageGuard` korumalı bir sayfa temiz bir
  ziyaretçi için hiçbir captcha widget'ı göstermiyor — bu yüzden pasif
  sinyal göndericisi, sayfada widget hiç yokken de çalışabilen, bağımsız,
  UI'sız küçük bir script olmak zorunda. `build_passive_risk_beacon_router()`
  hiçbir gate/parametre şart koşmadan sadece statik JS servis ediyor;
  `beacon.js` sayfa-geneli mouse takibi yapıp periyodik olarak (ve sayfa
  gizlenince `sendBeacon` ile son bir kez daha) `/api/captcha/passive-signal`'a
  POST atıyor.

Hepsi tamamen ek/opt-in: `risk_engine=None`/`running_risk_store=None`
davranışı değişmedi, mevcut hiçbir sinyalin/`RepeatedMovementCheck`'in
varsayılan çağrı şekli etkilenmedi. 300 test yeşil (271 → 300), ruff/mypy
temiz.
