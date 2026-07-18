# Geliştirici Notları (oturumlar arası kalıcı hafıza)

> Bu dosya, discord-webapi'de zaten kullanılan desenin aynısı:
> harici/git-tracked olmayan plan dosyaları oturumlar arası kaybolabiliyor
> ya da bulması zorlaşıyor, bu yüzden kalıcı mimari kararlar burada
> (repo'nun kendi içinde, git ile push edilerek) tutuluyor.
> `CHANGELOG.md` neyin değiştiğini, bu dosya NEDEN öyle tasarlandığını
> anlatıyor.

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
