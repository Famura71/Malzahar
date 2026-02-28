#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <csignal>
#include <regex>
#include <stdexcept>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

std::string logined_ad = "";
std::string logined_sifre = "";
std::vector<unsigned char> g_last_push_aes_key;
std::string g_last_push_payload;
std::string g_last_push_control_payload;
std::string g_last_push_scope;
std::string g_last_push_klasor;
std::string g_last_push_source_path;

// === CONFIG ===
const std::wstring HOST_W = L"www.famura.site";
const std::wstring TRANSFER_PATH = L"/api/private/transfer";
const std::wstring TRANSFER_ZIP_PATH = L"/api/private/transfer/zip";
const std::wstring PUSHZIP_PATH = L"/api/private/transfer/pushzip";
const std::string EMBED_HMAC_KEY = "";
const std::string EMBED_PRIVATE_KEY_PEM = "";
const std::string HMAC_KEY_FILE = "hmac.key";
const std::string PRIVATE_KEY_FILE = "private_key.pem";
std::string g_hmac_key;
std::string g_private_key_pem;

// RSA public key (X.509 SubjectPublicKeyInfo, base64)
const std::string RSA_PUBLIC_KEY_B64 =
"MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBlvH2wJJHUbb+uBaSUPShD3c07xFOWydEt1CmITi6CxY5CTTtS0Pqicqxlc6KQ9+Z8P4/oTX6bqU05pwrzmgj1f75/EC2qyXC1A2UWEBMTbpbQFfF5q31W4H0GN0xozYzXdTtf7uwWu85uc91DV+grT9PzrzONsxUJJE7o7sg+OzEwWJOZdgh64nZTwotUgmVYtVAxXWTdIFoS68+Jny5pGY3DQQO+cLvDZP4Zk9o7udQNoSLGMPp0zWycCMTWpf9drwEdqt6i/llyvsl4Dp1trDHWgTi3YeZZ1NkNbQfrxK92nA/6Ply1iePs0HNAKqcPgkBQfqIh6FlLuzHqUI9NAgMBAAE=";

volatile bool g_interrupted = false;
void signalHandler(int) { g_interrupted = true; }

static std::vector<std::string> split(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> out;
    for (std::string tok; iss >> tok;) out.push_back(tok);
    return out;
}

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

static std::string read_text_file_or_empty(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool init_secrets() {
    g_hmac_key = trim(EMBED_HMAC_KEY);
    g_private_key_pem = EMBED_PRIVATE_KEY_PEM;

    if (g_hmac_key.empty()) {
        g_hmac_key = trim(read_text_file_or_empty(std::filesystem::current_path() / HMAC_KEY_FILE));
    }
    if (g_private_key_pem.empty()) {
        g_private_key_pem = read_text_file_or_empty(std::filesystem::current_path() / PRIVATE_KEY_FILE);
    }
    if (g_hmac_key.empty() || g_private_key_pem.empty()) {
        return false;
    }
    return true;
}

static bool try_rsa_oaep_decrypt(EVP_PKEY* pkey,
    const std::vector<unsigned char>& encrypted,
    const EVP_MD* oaepMd,
    const EVP_MD* mgf1Md,
    std::vector<unsigned char>& out) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) return false;

    bool ok = false;
    size_t outLen = 0;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaepMd) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1Md) <= 0) goto cleanup;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, encrypted.data(), encrypted.size()) <= 0) goto cleanup;

    out.resize(outLen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outLen, encrypted.data(), encrypted.size()) <= 0) goto cleanup;
    out.resize(outLen);
    ok = true;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

std::vector<unsigned char> rsa_decrypt_with_private_key(const std::string& privkey_pem, const std::vector<unsigned char>& encrypted) {
    BIO* bio = BIO_new_mem_buf(privkey_pem.data(), (int)privkey_pem.size());
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("PEM_read_bio_PrivateKey failed");

    std::vector<unsigned char> out;

    // Java "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" decryption compatibility:
    // first try SHA-256 + MGF1-SHA1 (common JCE default), then SHA-256 + MGF1-SHA256.
    bool ok = try_rsa_oaep_decrypt(pkey, encrypted, EVP_sha256(), EVP_sha1(), out)
        || try_rsa_oaep_decrypt(pkey, encrypted, EVP_sha256(), EVP_sha256(), out)
        || try_rsa_oaep_decrypt(pkey, encrypted, EVP_sha1(), EVP_sha1(), out);

    EVP_PKEY_free(pkey);
    if (!ok) {
        unsigned long err = ERR_get_error();
        std::string errText = err ? ERR_error_string(err, nullptr) : "unknown";
        throw std::runtime_error("RSA OAEP decrypt failed: " + errText);
    }
    return out;
}
// Basit JSON ayrıştırıcı (sadece düz key-value için yeterli)
static std::string json_get_value(const std::string& json, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(json, m, re) && m.size() > 1) {
        return m[1].str();
    }
    return "";
}

// AES-GCM çözme fonksiyonu
std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    DWORD cbKeyObj = 0, cbData = 0, cbPlain = 0;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptSetProperty failed"); }
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(cbKeyObj), &cbData, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptGetProperty failed"); }
    std::vector<unsigned char> keyObj(cbKeyObj);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbKeyObj, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptGenerateSymmetricKey failed"); }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbTag = (PUCHAR)tag.data();
    authInfo.cbTag = (ULONG)tag.size();
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;
    std::vector<unsigned char> plain(ciphertext.size());
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &cbPlain, 0);
    if (status != 0) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptDecrypt(GCM) failed");
    }
    plain.resize(cbPlain);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return plain;
}

std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), size);
    return w;
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    DWORD outLen = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<unsigned char> hmac_sha256(const std::string& key, const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashObjectSize = 0, dataLen = 0, hashLen = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(hashObjectSize), &dataLen, 0) != 0)
        throw std::runtime_error("BCryptGetProperty failed");

    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &dataLen, 0) != 0)
        throw std::runtime_error("BCryptGetProperty failed");

    std::vector<unsigned char> hashObject(hashObjectSize);
    std::vector<unsigned char> hash(hashLen);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize,
        (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0)
        throw std::runtime_error("BCryptCreateHash failed");

    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return hash;
}

static std::string escape_single_quotes_ps(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\'') out += "''";
        else out.push_back(c);
    }
    return out;
}

static std::string find_connected_path(const std::string& scope, const std::string& klasor) {
    std::filesystem::path iniPath = std::filesystem::current_path() / "paths.ini";
    std::ifstream infile(iniPath);
    if (!infile.is_open()) return "";

    const std::string prefix = scope + "," + klasor + "-";
    std::string line;
    while (std::getline(infile, line)) {
        std::string t = trim(line);
        if (t.rfind(prefix, 0) == 0) {
            return trim(t.substr(prefix.size()));
        }
    }
    return "";
}

static int json_get_int_value(const std::string& json, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
    std::smatch m;
    if (std::regex_search(json, m, re) && m.size() > 1) {
        try {
            return std::stoi(m[1].str());
        }
        catch (...) {
            return -1;
        }
    }
    return -1;
}

static std::string yetki_seviyesi_adi(int level) {
    switch (level) {
    case 0: return "Public Puller";
    case 1: return "Public Puller + Pusher";
    case 2: return "Public Admin";
    case 3: return "Private Puller";
    case 4: return "Private Puller + Pusher";
    case 5: return "Private Admin";
    case 6: return "Public Admin + Private Puller";
    case 7: return "Public Admin + Private Puller + Pusher";
    case 8: return "Private Admin + Public Puller";
    case 9: return "Private Admin + Public Puller + Pusher";
    case 10: return "Public Puller + Private Puller";
    case 11: return "Private Puller + Pusher + Public Puller";
    case 12: return "Private Puller + Public Puller + Pusher";
    case 13: return "Public Puller + Pusher + Private Puller + Pusher";
    case 14: return "Genel Admin";
    default: return "Bilinmeyen Yetki";
    }
}

static int parse_response_code(const std::string& resp) {
    std::string t = trim(resp);
    if (t.empty()) return -1;
    size_t sep = t.find('|');
    std::string codePart = (sep == std::string::npos) ? t : t.substr(0, sep);
    std::regex re("^\\s*(-?\\d+)\\s*$");
    std::smatch m;
    if (std::regex_match(codePart, m, re) && m.size() > 1) {
        try {
            return std::stoi(m[1].str());
        }
        catch (...) {
            return -1;
        }
    }
    return -1;
}

static std::string server_code_desc(int code) {
    switch (code) {
    case 0: return "Basarili";
    case 1: return "Imza/HMAC veya payload format hatasi";
    case 2: return "RSA decrypt / JSON parse / genel format hatasi";
    case 3: return "Kullanici yok";
    case 4: return "Sifre yanlis";
    case 5: return "Istenen resource/versiyon yok";
    case 6: return "Yetki yok";
    default: return "Bilinmeyen kod";
    }
}

static std::string format_server_response(const std::string& resp) {
    int code = parse_response_code(resp);
    if (code < 0) return "Server response: " + resp;
    return "Server response: " + std::to_string(code) + " (" + server_code_desc(code) + ")";
}

static void clear_directory_contents(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir)) return;
    if (!std::filesystem::is_directory(dir)) {
        throw std::runtime_error("Target path is not a directory");
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        std::filesystem::remove_all(entry.path());
    }
}

static bool extract_zip_with_powershell(const std::filesystem::path& zipFile, const std::filesystem::path& destination) {
    std::string zip = escape_single_quotes_ps(zipFile.string());
    std::string dest = escape_single_quotes_ps(destination.string());
    std::string cmd = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Expand-Archive -LiteralPath '"
        + zip + "' -DestinationPath '" + dest + "' -Force | Out-Null\"";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

static bool create_zip_with_powershell(const std::filesystem::path& sourceDir, const std::filesystem::path& zipFile) {
    std::string src = escape_single_quotes_ps(sourceDir.string());
    std::string zip = escape_single_quotes_ps(zipFile.string());
    std::string cmd =
        "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "if (!(Test-Path -LiteralPath '" + src + "')) { exit 2 };"
        "$items = Get-ChildItem -LiteralPath '" + src + "' -Force;"
        "if ($items.Count -eq 0) { exit 3 };"
        "Compress-Archive -Path '" + src + "\\*' -DestinationPath '" + zip + "' -Force | Out-Null\"";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

static std::string flatten_single_root_folder_if_needed(const std::filesystem::path& destination) {
    std::vector<std::filesystem::path> entries;
    for (const auto& entry : std::filesystem::directory_iterator(destination)) {
        entries.push_back(entry.path());
    }

    if (entries.size() != 1) return "";
    const auto& only = entries[0];
    if (!std::filesystem::is_directory(only)) return "";

    std::string movedFolderName = only.filename().string();
    std::vector<std::filesystem::path> inner;
    for (const auto& entry : std::filesystem::directory_iterator(only)) {
        inner.push_back(entry.path());
    }

    for (const auto& src : inner) {
        std::filesystem::path dest = destination / src.filename();
        std::filesystem::rename(src, dest);
    }
    std::filesystem::remove(only);
    return movedFolderName;
}

static std::vector<unsigned char> read_binary_file(const std::filesystem::path& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in.is_open()) {
        throw std::runtime_error("Cannot open file for reading");
    }
    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size < 0) {
        throw std::runtime_error("Invalid file size");
    }
    std::vector<unsigned char> data(static_cast<size_t>(size));
    if (size > 0) {
        in.read(reinterpret_cast<char*>(data.data()), size);
        if (!in) {
            throw std::runtime_error("Cannot read file data");
        }
    }
    return data;
}

static std::vector<unsigned char> generate_aes_key_256() {
    std::vector<unsigned char> key(32);
    if (BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
    return key;
}

static std::vector<unsigned char> generate_random_iv_12() {
    std::vector<unsigned char> iv(12);
    if (BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
    return iv;
}

static std::string aes_gcm_encrypt_payload(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plain) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD cbKeyObj = 0, cbData = 0, cbCipher = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptSetProperty failed"); }
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(cbKeyObj), &cbData, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptGetProperty failed"); }

    std::vector<unsigned char> keyObj(cbKeyObj);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbKeyObj, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptGenerateSymmetricKey failed"); }

    std::vector<unsigned char> iv = generate_random_iv_12();
    std::vector<unsigned char> tag(16);
    std::vector<unsigned char> cipher(plain.size());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbTag = (PUCHAR)tag.data();
    authInfo.cbTag = (ULONG)tag.size();
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;

    status = BCryptEncrypt(hKey,
        (PUCHAR)plain.data(), (ULONG)plain.size(),
        &authInfo,
        nullptr, 0,
        cipher.data(), (ULONG)cipher.size(), &cbCipher, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0) {
        throw std::runtime_error("BCryptEncrypt(GCM) failed");
    }
    cipher.resize(cbCipher);

    return base64_encode(iv) + "|" + base64_encode(cipher) + "|" + base64_encode(tag);
}

std::vector<unsigned char> base64_decode(const std::string& b64) {
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) {
        throw std::runtime_error("CryptStringToBinaryA size failed");
    }
    std::vector<unsigned char> out(outLen);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr)) {
        throw std::runtime_error("CryptStringToBinaryA failed");
    }
    out.resize(outLen);
    return out;
}

static bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string verify_and_decrypt_signed_payload(const std::string& signedPayload) {
    size_t sep = signedPayload.find('|');
    if (sep == std::string::npos || sep == 0 || sep == signedPayload.size() - 1) {
        throw std::runtime_error("Invalid signed payload format");
    }

    std::string encryptedB64 = signedPayload.substr(0, sep);
    std::string signatureB64 = signedPayload.substr(sep + 1);
    std::string expectedSignatureB64 = base64_encode(hmac_sha256(g_hmac_key, encryptedB64));

    if (!constant_time_equal(signatureB64, expectedSignatureB64)) {
        throw std::runtime_error("Response signature verification failed");
    }

    std::vector<unsigned char> encrypted = base64_decode(encryptedB64);
    std::vector<unsigned char> plain = rsa_decrypt_with_private_key(g_private_key_pem, encrypted);
    return std::string(plain.begin(), plain.end());
}

std::vector<unsigned char> rsa_encrypt_oaep_spki(const std::vector<unsigned char>& spkiDer,
    const std::vector<unsigned char>& data) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    CERT_PUBLIC_KEY_INFO* pInfo = nullptr;
    DWORD cbInfo = 0;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        spkiDer.data(), (DWORD)spkiDer.size(),
        CRYPT_DECODE_ALLOC_FLAG, nullptr, &pInfo, &cbInfo)) {
        throw std::runtime_error("CryptDecodeObjectEx failed");
    }

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pInfo, 0, nullptr, &hKey)) {
        LocalFree(pInfo);
        throw std::runtime_error("CryptImportPublicKeyInfoEx2 failed");
    }

    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = nullptr;
    paddingInfo.cbLabel = 0;

    DWORD outLen = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)data.data(), (ULONG)data.size(),
        &paddingInfo, nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_OAEP);
    std::vector<unsigned char> out(outLen);
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), (ULONG)data.size(),
        &paddingInfo, nullptr, 0, out.data(), (ULONG)out.size(), &outLen, BCRYPT_PAD_OAEP);

    BCryptDestroyKey(hKey);
    LocalFree(pInfo);

    out.resize(outLen);
    return out;
}

std::string build_signed_payload(const std::string& encryptedBase64) {
    auto sig = hmac_sha256(g_hmac_key, encryptedBase64);
    std::string sigB64 = base64_encode(sig);
    return encryptedBase64 + "|" + sigB64;
}

std::string build_signed_request_payload(const std::string& request, const std::string& name, const std::string& password, const std::string& data) {
    std::string json = "{\"request\":\"" + request + "\",\"name\":\"" + name + "\",\"password\":\"" + password + "\",\"data\":\"" + data + "\"}";

    std::vector<unsigned char> spki = base64_decode(RSA_PUBLIC_KEY_B64);
    std::vector<unsigned char> encrypted = rsa_encrypt_oaep_spki(spki,
        std::vector<unsigned char>(json.begin(), json.end()));
    std::string encryptedB64 = base64_encode(encrypted);

    return build_signed_payload(encryptedB64);
}

std::string http_post_raw(const std::wstring& path, const std::string& body, const std::wstring& contentType = L"application/octet-stream") {
    HINTERNET hSession = WinHttpOpen(L"Malzahar/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, HOST_W.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    std::wstring headers = L"Content-Type: " + contentType + L"\r\n";
    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1,
        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, nullptr);

    std::string response;
    if (ok) {
        DWORD size = 0;
        do {
            DWORD downloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &size)) break;
            if (size == 0) break;
            std::vector<char> buf(size + 1);
            if (!WinHttpReadData(hRequest, buf.data(), size, &downloaded)) break;
            buf[downloaded] = '\0';
            response.append(buf.data(), downloaded);
        } while (size > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

std::string send_request(const std::string& request, const std::string& name, const std::string& password, const std::string& data) {
    std::string payload = build_signed_request_payload(request, name, password, data);
    return http_post_raw(TRANSFER_PATH, payload);
}

int main() {
    if (!init_secrets()) {
        std::cout << "Missing secrets. Set EMBED_* in code or provide files: "
            << HMAC_KEY_FILE << " and " << PRIVATE_KEY_FILE << "\n";
        return 1;
    }

    std::signal(SIGINT, signalHandler);
    std::cout << "Malzahar.exe: (type 'help')\n";

    while (!g_interrupted) {
        std::cout << "Malzahar.exe> " << std::flush;
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (g_interrupted) break;
        if (line.empty()) continue;

        auto args = split(line);
        if (args.empty()) continue;
        const std::string& cmd = args[0];

        if (cmd == "exit" || cmd == "quit") break;
        if (cmd == "help") {
            std::cout
                << "Commands:\n"
                << "  login <ad>,<sifre>\n"
                << "  connect <Public|Private>,<klasor>\n"
                << "  check <Public|Private>,<klasor>\n"
                << "  pull <Public|Private>,<klasor>[,<versiyon>]\n"
                << "  push <Public|Private>,<klasor>\n"
                << "  manage <Public|Private>,<klasor>,<versiyon>\n";
            continue;
        }

        if (cmd == "login") {
            if (line.size() <= 6) { std::cout << "Usage: login <ad>,<sifre>\n"; continue; }
            std::string params = trim(line.substr(6));
            size_t comma = params.find(',');
            if (comma == std::string::npos) { std::cout << "Usage: login <ad>,<sifre>\n"; continue; }
            std::string ad = trim(params.substr(0, comma));
            std::string sifre = trim(params.substr(comma + 1));
            std::string resp = send_request("login", ad, sifre, "");
            if (!resp.empty() && resp[0] == '0') {
                logined_ad = ad;
                logined_sifre = sifre;

                // Expected format: 0|{"name":"...","yetki":N}
                std::string payload = (resp.size() > 2 && resp[1] == '|') ? resp.substr(2) : "";
                std::string userName = json_get_value(payload, "name");
                int yetki = json_get_int_value(payload, "yetki");

                if (!userName.empty() && yetki >= 0) {
                    std::cout << userName << " - " << yetki_seviyesi_adi(yetki) << "\n";
                }
                else {
                    std::cout << format_server_response(resp) << "\n";
                }
            }
            else {
                std::cout << format_server_response(resp) << "\n";
            }
            continue;
        }

        if (cmd == "connect") {
            if (logined_ad.empty() || logined_sifre.empty()) { std::cout << "please login first\n"; continue; }
            if (line.size() <= 8) { std::cout << "Usage: connect <Public|Private>,<klasor>,<path>\n"; continue; }
            std::string params = trim(line.substr(8));
            size_t c1 = params.find(',');
            if (c1 == std::string::npos) { std::cout << "Usage: connect <Public|Private>,<klasor>,<path>\n"; continue; }
            std::string scope = trim(params.substr(0, c1));
            std::string rest = trim(params.substr(c1 + 1));
            size_t c2 = rest.find(',');
            if (c2 == std::string::npos) { std::cout << "connect failed: path is required\n"; continue; }
            std::string klasor = trim(rest.substr(0, c2));
            std::string path = trim(rest.substr(c2 + 1));
            if (path.empty()) { std::cout << "connect failed: path is required\n"; continue; }
            std::string data = scope + "/" + klasor;
            std::string resp = send_request("connect", logined_ad, logined_sifre, data);
            std::cout << format_server_response(resp) << "\n";

            // Eğer path girilmişse ve sunucudan "0" cevabı geldiyse kaydet
            if (resp == "0") {
                std::string entry = scope + "," + klasor + "-" + path;
                std::filesystem::path iniPath = std::filesystem::current_path() / "paths.ini";
                std::ifstream infile(iniPath);
                bool exists = false;
                std::string line;
                while (std::getline(infile, line)) {
                    if (line.find(entry) == 0) { exists = true; break; }
                }
                infile.close();
                if (!exists) {
                    std::ofstream outfile(iniPath, std::ios::app);
                    outfile << entry << std::endl;
                }
            }
            continue;
        }

        if (cmd == "check") {
            if (logined_ad.empty() || logined_sifre.empty()) { std::cout << "please login first\n"; continue; }
            if (line.size() <= 6) { std::cout << "Usage: check <Public|Private>,<klasor>\n"; continue; }
            std::string params = trim(line.substr(6));
            size_t comma = params.find(',');
            if (comma == std::string::npos) { std::cout << "Usage: check <Public|Private>,<klasor>\n"; continue; }
            std::string scope = trim(params.substr(0, comma));
            std::string klasor = trim(params.substr(comma + 1));

            std::string targetPathStr = find_connected_path(scope, klasor);
            if (targetPathStr.empty()) {
                std::cout << "check failed: target path not found in paths.ini (run connect with path)\n";
                continue;
            }

            std::string data = scope + "/" + klasor;
            std::string resp = send_request("check", logined_ad, logined_sifre, data);
            if (resp.rfind("0|", 0) == 0 && resp.size() > 2) {
                std::cout << "Server response: 0 (Basarili) | " << resp.substr(2) << "\n";
            }
            else {
                std::cout << format_server_response(resp) << "\n";
            }
            continue;
        }

        if (cmd == "pull") {
            if (logined_ad.empty() || logined_sifre.empty()) { std::cout << "please login first\n"; continue; }
            if (line.size() <= 5) { std::cout << "Usage: pull <Public|Private>,<klasor>[,<versiyon>]\n"; continue; }
            std::string params = trim(line.substr(5));
            size_t c1 = params.find(',');
            if (c1 == std::string::npos) { std::cout << "Usage: pull <Public|Private>,<klasor>[,<versiyon>]\n"; continue; }
            std::string scope = trim(params.substr(0, c1));
            std::string rest = trim(params.substr(c1 + 1));
            size_t c2 = rest.find(',');
            std::string klasor = (c2 == std::string::npos) ? rest : trim(rest.substr(0, c2));
            std::string version = (c2 == std::string::npos) ? "" : trim(rest.substr(c2 + 1));
            std::string data = scope + "/" + klasor + (version.empty() ? "" : "/" + version);

            std::string targetPathStr = find_connected_path(scope, klasor);
            if (targetPathStr.empty()) {
                std::cout << "pull failed: target path not found in paths.ini (run connect with path)\n";
                continue;
            }

            try {
                // 1) pull yanitinin imzasini dogrula, 2) kalan RSA verisini private key ile ac.
                std::string signedResp = send_request("pull", logined_ad, logined_sifre, data);
                std::string resp = verify_and_decrypt_signed_payload(signedResp);

                // Server response format: {"response":"0 aes key : <base64>"}
                std::string response_value = json_get_value(resp, "response");
                const std::string keyPrefix = "0 aes key : ";
                if (response_value.rfind(keyPrefix, 0) == 0) {
                    std::string aesKey_b64 = trim(response_value.substr(keyPrefix.size()));
                    if (aesKey_b64.empty()) {
                        std::cout << "pull failed: empty aes key\n";
                        continue;
                    }
                    std::vector<unsigned char> aesKey = base64_decode(aesKey_b64);

                    // pull zip endpoint returns plaintext iv|ciphertext|tag (AES-GCM), not RSA/HMAC.
                    std::string encdata_resp = http_post_raw(TRANSFER_ZIP_PATH, "pull", L"text/plain");

                    size_t p1 = encdata_resp.find('|');
                    size_t p2 = encdata_resp.find('|', p1 + 1);
                    if (p1 == std::string::npos || p2 == std::string::npos) {
                        std::cout << "pull failed: invalid zip payload format\n";
                        continue;
                    }
                    std::string iv_b64 = encdata_resp.substr(0, p1);
                    std::string ct_b64 = encdata_resp.substr(p1 + 1, p2 - p1 - 1);
                    std::string tag_b64 = encdata_resp.substr(p2 + 1);
                    std::vector<unsigned char> iv = base64_decode(iv_b64);
                    std::vector<unsigned char> ct = base64_decode(ct_b64);
                    std::vector<unsigned char> tag = base64_decode(tag_b64);
                    std::vector<unsigned char> plain = aes_gcm_decrypt(aesKey, iv, ct, tag);

                    std::filesystem::path targetPath = targetPathStr;
                    std::filesystem::create_directories(targetPath);
                    clear_directory_contents(targetPath);

                    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
                    std::filesystem::path tempZip = std::filesystem::temp_directory_path() /
                        ("malzahar_pull_" + std::to_string(now) + ".zip");

                    {
                        std::ofstream out(tempZip, std::ios::binary);
                        if (!out.is_open()) {
                            std::cout << "pull failed: cannot create temp zip file\n";
                            continue;
                        }
                        out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
                    }

                    bool extracted = extract_zip_with_powershell(tempZip, targetPath);
                    std::error_code ec;
                    std::filesystem::remove(tempZip, ec);

                    if (!extracted) {
                        std::cout << "pull failed: zip extraction failed\n";
                        continue;
                    }

                    std::string rootFolder = flatten_single_root_folder_if_needed(targetPath);
                    std::string versionInfo = version.empty() ? (rootFolder.empty() ? "latest" : rootFolder) : version;
                    std::cout << "pull ok: version=" << versionInfo
                        << ", extracted to " << targetPath.string() << "\n";
                } else {
                    std::cout << format_server_response(resp) << "\n";
                }
            } catch (const std::exception& ex) {
                std::cout << "pull failed: " << ex.what() << "\n";
            }
            continue;
        }

        if (cmd == "manage") {
            if (logined_ad.empty() || logined_sifre.empty()) { std::cout << "please login first\n"; continue; }
            if (line.size() <= 7) { std::cout << "Usage: manage <Public|Private>,<klasor>,<versiyon>\n"; continue; }
            std::string params = trim(line.substr(7));
            size_t c1 = params.find(',');
            if (c1 == std::string::npos) { std::cout << "Usage: manage <Public|Private>,<klasor>,<versiyon>\n"; continue; }
            std::string scope = trim(params.substr(0, c1));
            std::string rest = trim(params.substr(c1 + 1));
            size_t c2 = rest.find(',');
            if (c2 == std::string::npos) { std::cout << "Usage: manage <Public|Private>,<klasor>,<versiyon>\n"; continue; }
            std::string klasor = trim(rest.substr(0, c2));
            std::string version = trim(rest.substr(c2 + 1));

            std::string targetPathStr = find_connected_path(scope, klasor);
            if (targetPathStr.empty()) {
                std::cout << "manage failed: target path not found in paths.ini (run connect with path)\n";
                continue;
            }

            std::string data = scope + "/" + klasor + "/" + version;
            std::string resp = send_request("manage", logined_ad, logined_sifre, data);
            std::cout << format_server_response(resp) << "\n";
            continue;
        }

        if (cmd == "push") {
            if (logined_ad.empty() || logined_sifre.empty()) { std::cout << "please login first\n"; continue; }
            if (line.size() <= 5) { std::cout << "Usage: push <Public|Private>,<klasor>\n"; continue; }
            std::string params = trim(line.substr(5));
            size_t c1 = params.find(',');
            if (c1 == std::string::npos) { std::cout << "Usage: push <Public|Private>,<klasor>\n"; continue; }
            std::string scope = trim(params.substr(0, c1));
            std::string klasor = trim(params.substr(c1 + 1));
            if (scope.empty() || klasor.empty()) { std::cout << "Usage: push <Public|Private>,<klasor>\n"; continue; }

            std::string targetPathStr = find_connected_path(scope, klasor);
            if (targetPathStr.empty()) {
                std::cout << "push failed: target path not found in paths.ini (run connect with path)\n";
                continue;
            }

            try {
                std::filesystem::path sourcePath = targetPathStr;
                if (!std::filesystem::exists(sourcePath) || !std::filesystem::is_directory(sourcePath)) {
                    std::cout << "push failed: source path is missing or not a directory\n";
                    continue;
                }

                std::cout << "push: creating zip from " << sourcePath.string() << " ...\n";
                auto now = std::chrono::steady_clock::now().time_since_epoch().count();
                std::filesystem::path tempZip = std::filesystem::temp_directory_path() /
                    ("malzahar_push_" + std::to_string(now) + ".zip");

                if (!create_zip_with_powershell(sourcePath, tempZip)) {
                    std::cout << "push failed: zip create failed (folder may be empty)\n";
                    continue;
                }

                std::cout << "push: encrypting zip payload ...\n";
                std::vector<unsigned char> zipBytes = read_binary_file(tempZip);
                std::error_code ec;
                std::filesystem::remove(tempZip, ec);

                std::vector<unsigned char> aesKey = generate_aes_key_256();
                std::string encryptedPayload = aes_gcm_encrypt_payload(aesKey, zipBytes);
                std::string aesKeyB64 = base64_encode(aesKey);
                std::string pushData = scope + "/" + klasor + "/" + aesKeyB64;
                std::string pushControlPayload = build_signed_request_payload("push", logined_ad, logined_sifre, pushData);

                g_last_push_aes_key = std::move(aesKey);
                g_last_push_payload = std::move(encryptedPayload);
                g_last_push_control_payload = std::move(pushControlPayload);
                g_last_push_scope = scope;
                g_last_push_klasor = klasor;
                g_last_push_source_path = targetPathStr;

                std::cout << "push precheck ok: encrypted payload prepared, key-len=" << g_last_push_aes_key.size()
                    << ", payload-bytes=" << g_last_push_payload.size()
                    << ", control-bytes=" << g_last_push_control_payload.size() << "\n";

                std::cout << "push: sending control payload ...\n";
                std::string controlResp = trim(http_post_raw(TRANSFER_PATH, g_last_push_control_payload));
                if (controlResp != "0") {
                    std::cout << "push failed: control step rejected, " << format_server_response(controlResp) << "\n";
                    continue;
                }

                std::cout << "push: control step accepted, sending zip payload ...\n";
                std::string zipResp = trim(http_post_raw(PUSHZIP_PATH, g_last_push_payload));
                if (zipResp != "0") {
                    std::cout << "push failed: zip upload rejected, " << format_server_response(zipResp) << "\n";
                    continue;
                }

                std::cout << "push ok: zip uploaded successfully\n";
            }
            catch (const std::exception& ex) {
                std::cout << "push failed: " << ex.what() << "\n";
            }
            continue;
        }

        int rc = std::system(line.c_str());
        std::cout << "(exit code: " << rc << ")\n";
    }

    std::cout << "Bye.\n";
    return 0;
}
