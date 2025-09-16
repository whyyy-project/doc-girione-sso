# GiriOne SSO – Panduan Integrasi Client

Dokumen ini menjelaskan integrasi OAuth2 Authorization Code Flow (tanpa Passport) untuk aplikasi client (web/mobile) terhadap SSO Server GiriOne. Tersedia 2 skenario:

- SSO-initiated login: pengguna klik aplikasi dari Dashboard SSO → langsung diarahkan ke client dengan `code`.
- Client-initiated login: pengguna berada di aplikasi client lalu klik "Login via SSO" → diarahkan ke SSO untuk otentikasi, kembali ke client dengan `code`.

SSO juga mendukung Refresh Token, Revoke, Throttle dasar (rate limit) pada endpoint sensitif, validasi `state`/`nonce`, dan opsional PKCE.

## 1. Terminologi & Alur Tinggi

- Authorization Code Flow: client menerima `code` (sekali pakai), menukarnya ke Access Token + Refresh Token via endpoint `/token`.
- Access Token (JWT): dipakai untuk akses API client atau untuk memanggil `/me` di SSO (profil pengguna + permissions) jika diperlukan.
- Refresh Token: dipakai untuk mendapatkan Access Token baru tanpa login ulang.
- state: proteksi CSRF; harus di-echo kembali saat redirect dari SSO.
- nonce: proteksi replay; dibawa pada saat authorize, dicantumkan di JWT claim bila di-set.
- PKCE (opsional): untuk public client (mobile/Spa). Untuk confidential web client, boleh tidak menggunakan PKCE.

## 2. Endpoint SSO

Base URL SSO Server (contoh): `https://sso.unugiri.ac.id`

- GET `/auth`
  - Tujuan: Memulai alur authorize. Jika user sudah login di SSO, SSO langsung mengembalikan `code` ke `redirect_uri`. Jika belum, SSO menampilkan form login.
  - Query parameters:
    - `client_id` (required)
    - `redirect_uri` (required, harus persis sama dengan yang terdaftar di SSO)
    - `response_type=code`
    - `state` (recommended)
    - `nonce` (optional)
    - `code_challenge` (optional, untuk PKCE)
    - `code_challenge_method` (optional: `plain` atau `S256`)

- POST `/api/token`
  - Tujuan: Menukar `code` menjadi `access_token` dan `refresh_token` (grant_type `authorization_code`) atau memutar `refresh_token` (grant_type `refresh_token`).
  - Endpoint ini diberi rate limiting (throttling) di sisi SSO untuk mitigasi abuse.
  - Body (authorization_code):
    - `grant_type=authorization_code`
    - `client_id`, `client_secret`
    - `code`
    - (PKCE) `code_verifier` jika `code_challenge` digunakan saat authorize
  - Body (refresh_token):
    - `grant_type=refresh_token`
    - `client_id`, `client_secret`
    - `refresh_token`

- GET `/api/me` (Bearer)
  - Tujuan: Mengambil profil user terautentikasi di SSO + effective permissions.
  - Header: `Authorization: Bearer <access_token>`

Catatan: `/token` dan `/me` berada di namespace API (bebas CSRF). `/auth` berada di web (menangani UI login dan redirect).

## 3. Data Model Client pada SSO

Setiap client yang didaftarkan memiliki:
- `client_id` (public)
- `client_secret` (rahasia; hanya ditampilkan sekali saat dibuat/reset)
- `redirect_uri` (harus tepat)
- `status` (aktif/nonaktif)

Pastikan `redirect_uri` di client sama persis dengan yang tersimpan di SSO (termasuk scheme, domain, path, dan trailing slash bila ada).

## 4. Skenario A – SSO-Initiated Login (Klik dari Dashboard SSO)

1) Pengguna sudah login di SSO dan melihat daftar aplikasi yang dapat diakses.
2) Pengguna klik ikon aplikasi. Dashboard SSO akan diarahkan ke url login sso sistem client, contoh `https://simutu.unugiri.ac.id/girione/auth`.
3) 
## 5. Skenario B – Client-Initiated Login (Klik tombol di Client)

1) Client membuat `state` acak (wajib disimpan sementara di session/cookie) dan opsional `nonce`.
2) Redirect user ke:

```
GET https://sso.unugiri.ac.id/auth?client_id=CLIENT_ID&redirect_uri=URLENCODED_REDIRECT&response_type=code&state=XYZ&nonce=ABC
```

3) Setelah user login (atau sudah login), SSO redirect balik ke `redirect_uri` dengan `code` dan `state`.
4) Client validasi `state`, lalu tukar `code` via `/api/token`.

Jika public client/mobile menggunakan PKCE, tambahkan `code_challenge`/`code_challenge_method=S256` pada langkah (2), dan kirim `code_verifier` saat tukar token.

## 6. Contoh Implementasi (Laravel Client)

### 6.1. ENV Client

```
SSO_BASE_URL=https://sso.unugiri.ac.id
SSO_CLIENT_ID=your_client_id
SSO_CLIENT_SECRET=your_client_secret
SSO_REDIRECT_URI=https://client.example.com/auth/callback
```

### 6.2. Route Client

```php
// routes/web.php
Route::get('/login/sso', [SSOClientController::class, 'redirect'])->name('sso.login');
Route::get('/auth/callback', [SSOClientController::class, 'callback'])->name('sso.callback');
```

### 6.3. Controller Client (ringkas)

```php
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;

class SSOClientController extends Controller
{
    public function redirect()
    {
        $state = Str::random(24);
        session(['sso_state' => $state]);
        $url = config('services.sso.base').'/auth?'.http_build_query([
            'client_id' => config('services.sso.client_id'),
            'redirect_uri' => config('services.sso.redirect_uri'),
            'response_type' => 'code',
            'state' => $state,
        ]);
        return redirect()->away($url);
    }

    public function callback(Request $request)
    {
        if ($request->state !== session('sso_state')) {
            abort(400, 'Invalid state');
        }

        $resp = Http::asForm()->post(config('services.sso.base').'/api/token', [
            'grant_type' => 'authorization_code',
            'client_id' => config('services.sso.client_id'),
            'client_secret' => config('services.sso.client_secret'),
            'code' => $request->code,
        ]);

        if (!$resp->ok()) {
            abort(400, 'Token exchange failed');
        }

        $tokens = $resp->json();
        // Simpan $tokens['access_token'], $tokens['refresh_token'], expired_at, dsb.

        // (Opsional) ambil profil dari SSO
        $me = Http::withToken($tokens['access_token'])
            ->get(config('services.sso.base').'/api/me')
            ->json();

        // Lakukan login di aplikasi client berdasarkan email/id dari $me
        // ...

        return redirect('/');
    }
}
```

### 6.4. Config Client (opsional)

```php
// config/services.php
return [
    'sso' => [
        'base' => env('SSO_BASE_URL'),
        'client_id' => env('SSO_CLIENT_ID'),
        'client_secret' => env('SSO_CLIENT_SECRET'),
        'redirect_uri' => env('SSO_REDIRECT_URI'),
    ],
];
```

## 7. Contoh cURL

- Tukar code → token:

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=YOUR_ID" \
  -d "client_secret=YOUR_SECRET" \
  -d "code=AUTH_CODE" \
  https://sso.unugiri.ac.id/api/token
```

- Refresh token:

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=YOUR_ID" \
  -d "client_secret=YOUR_SECRET" \
  -d "refresh_token=REFRESH_TOKEN" \
  https://sso.unugiri.ac.id/api/token
```

- Ambil profil:

```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  https://sso.unugiri.ac.id/api/me
```

## 8. Format Respons `/api/token`

Contoh sukses (authorization_code):

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque_or_jwt>",
  "scope": null
}
```

Contoh error:

```json
{ "error": "invalid_client" }
{ "error": "invalid_code" }
{ "error": "code_expired" }
{ "error": "invalid_grant", "error_description": "code_verifier mismatch" }
```

## 9. JWT `access_token`

- Ditandatangani dengan secret/keys yang didefinisikan di SSO (`.env`).
- Claim dapat berisi: `sub` (user id), `email`, `role`, `permissions` (efektif), `nonce` (jika dikirim saat authorize), `iat`, `exp`, `iss`, `aud`.
- Client boleh memverifikasi JWT (opsional) atau cukup mempercayai hasil `/api/token` bila komunikasi HTTPS.

## 10. Keamanan – Rekomendasi

- **Wajib** validasi `state` pada callback.
- Gunakan **HTTPS** untuk semua endpoint.
- Simpan `client_secret` hanya di server side (jangan di browser/mobile). Untuk public client gunakan **PKCE**.
- Simpan `refresh_token` dengan aman. Putar (rotate) saat refresh.
- Logout: bila perlu, hapus token lokal di client. (Jika diperlukan central-logout, koordinasikan endpoint tambahan.)
- Batasi `redirect_uri` 1:1, hindari wildcard.

## 11. Troubleshooting

- `redirect_uri mismatch`: pastikan sama persis (scheme/host/path/trailing slash).
- `invalid_client`: `client_id` tidak terdaftar atau `client_secret` salah.
- `invalid_code` / `code_expired`: code sudah terpakai/kedaluwarsa. Pastikan menukar hanya sekali dan dalam 5 menit.
- `Invalid state`: session/cookie state hilang atau berubah.
- CORS: `/token` dan `/me` adalah API; panggil dari server-side atau atur CORS sesuai kebutuhan bila SPA.

## 12. Ringkasan Langkah Integrasi

1) Dapatkan `client_id`, `client_secret`, `redirect_uri` terdaftar dari SSO Admin.
2) Implement route callback di client dan validasi `state`.
3) Implement tukar `code` → token via `/api/token` dan simpan token.
4) (Opsional) Ambil profil via `/api/me` dan sinkronkan user lokal.
5) (Opsional) Implement refresh token flow.
6) Uji kedua skenario: SSO-initiated (klik dari Dashboard SSO) dan Client-initiated (tombol Login via SSO).
