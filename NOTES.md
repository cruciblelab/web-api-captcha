# Geliştirici Notları (oturumlar arası kalıcı hafıza)

> Bu dosya, discord-webapi'de zaten kullanılan desenin aynısı:
> harici/git-tracked olmayan plan dosyaları oturumlar arası kaybolabiliyor
> ya da bulması zorlaşıyor, bu yüzden kalıcı mimari kararlar burada
> (repo'nun kendi içinde, git ile push edilerek) tutuluyor.
> `CHANGELOG.md` neyin değiştiğini, bu dosya NEDEN öyle tasarlandığını
> anlatıyor.

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
