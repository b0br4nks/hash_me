/**
 * Author: @NoamZeitoun
 * Category: Hashing
 * Description: Hash a string using various algorithms.
 */

window.onload = function(){
    document.getElementById("s-input").value = "";
    document.querySelectorAll(".l-input").value = "";
}

let salt = CryptoJS.lib.WordArray.random(128 / 8);

const hash = (str, algorithm) => {
  let hash = CryptoJS.algo[algorithm].create();
  hash.update(str);
  return hash.finalize();
};
// -------------let the magic happen----------------------
const hash_md5 = (str) => CryptoJS.MD5(str).toString();
const hash_sha256 = (str) => CryptoJS.SHA256(str).toString();
const hash_sha512 = (str) => CryptoJS.SHA512(str).toString();
const hash_sha3_256 = (str) =>
  CryptoJS.SHA3(str, { outputLength: 256 }).toString();
const hash_sha3_512 = (str) =>
  CryptoJS.SHA3(str, { outputLength: 512 }).toString();
const hash_sha1 = (str) => CryptoJS.SHA1(str).toString();
const hash_sha224 = (str) => CryptoJS.SHA224(str).toString();
const hash_sha384 = (str) => CryptoJS.SHA384(str).toString();
const hash_aes_256_cbc = (str) =>
  CryptoJS.AES.encrypt(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_ripemd160 = (str) => CryptoJS.RIPEMD160(str).toString();
const hash_evp_bytestokey = (str) =>
  CryptoJS.EvpKDF(str, "b0br4nksfr0mc4sp3rt34m", {
    keySize: 256 / 32,
    ivSize: 128 / 32,
    saltSize: 64 / 32,
  }).toString();
const hash_HmacMD5 = (str) =>
  CryptoJS.HmacMD5(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_HmacSHA1 = (str) =>
  CryptoJS.HmacSHA1(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_HmacSHA256 = (str) =>
  CryptoJS.HmacSHA256(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_HmacSHA512 = (str) =>
  CryptoJS.HmacSHA512(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_PBKDF2128 = (str) =>
  CryptoJS.PBKDF2(str, salt, { keySize: 128 / 32 }).toString();
const hash_PBKDF2256 = (str) =>
  CryptoJS.PBKDF2(str, salt, { keySize: 256 / 32 }).toString();
const hash_PBKDF2512 = (str) =>
  CryptoJS.PBKDF2(str, salt, { keySize: 512 / 32 }).toString();
const hash_PBKDF2512_1000 = (str) =>
  CryptoJS.PBKDF2(str, salt, {
    keySize: 512 / 32,
    iterations: 1000,
  }).toString();
const hash_DES = (str) =>
  CryptoJS.DES.encrypt(str, "b0br4nksfr0mc4sp3rt34m", {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  }).toString();
const hash_rabbit = (str) =>
  CryptoJS.Rabbit.encrypt(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_RC4 = (str) =>
  CryptoJS.RC4.encrypt(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_RC4drop = (str) =>
  CryptoJS.RC4Drop.encrypt(str, "b0br4nksfr0mc4sp3rt34m").toString();
const hash_base64 = (str) =>
  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(str));
const hash_latin1 = (str) =>
  CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Utf8.parse(str));
const hash_hex = (str) =>
  CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(str));
// -------------------------------------------------------------------
const hash_me = () => {
  const s = document.getElementById("s-input").value;
  if (s.length == 0)
    document.getElementById("s").value = "please enter a string";
  const md5 = hash_md5(s);
  document.getElementById("md5").value = md5;
  const sha256 = hash_sha256(s);
  document.getElementById("sha256").value = sha256;
  const sha512 = hash_sha512(s);
  document.getElementById("sha512").value = sha512;
  const sha3_256 = hash_sha3_256(s);
  document.getElementById("sha3_256").value = sha3_256;
  const sha3_512 = hash_sha3_512(s);
  document.getElementById("sha3_512").value = sha3_512;
  const sha1 = hash_sha1(s);
  document.getElementById("sha1").value = sha1;
  const sha224 = hash_sha224(s);
  document.getElementById("sha224").value = sha224;
  const sha384 = hash_sha384(s);
  document.getElementById("sha384").value = sha384;
  const aes_256_cbc = hash_aes_256_cbc(s);
  document.getElementById("aes_256_cbc").value = aes_256_cbc;
  const ripemd160 = hash_ripemd160(s);
  document.getElementById("ripemd160").value = ripemd160;
  const evp_bytestokey = hash_evp_bytestokey(s);
  document.getElementById("evp_bytestokey").value = evp_bytestokey;
  const HmacMD5 = hash_HmacMD5(s);
  document.getElementById("HmacMD5").value = HmacMD5;
  const HmacSHA1 = hash_HmacSHA1(s);
  document.getElementById("HmacSHA1").value = HmacSHA1;
  const HmacSHA256 = hash_HmacSHA256(s);
  document.getElementById("HmacSHA256").value = HmacSHA256;
  const HmacSHA512 = hash_HmacSHA512(s);
  document.getElementById("HmacSHA512").value = HmacSHA512;
  const PBKDF2128 = hash_PBKDF2128(s);
  document.getElementById("PBKDF2128").value = PBKDF2128;
  const PBKDF2256 = hash_PBKDF2256(s);
  document.getElementById("PBKDF2256").value = PBKDF2256;
  const PBKDF2512 = hash_PBKDF2512(s);
  document.getElementById("PBKDF2512").value = PBKDF2512;
  const PBKDF2512_1000 = hash_PBKDF2512_1000(s);
  document.getElementById("PBKDF2512_1000").value = PBKDF2512_1000;
  const DES = hash_DES(s);
  document.getElementById("DES").value = DES;
  const rabbit = hash_rabbit(s);
  document.getElementById("rabbit").value = rabbit;
  const RC4 = hash_RC4(s);
  document.getElementById("RC4").value = RC4;
  const RC4drop = hash_RC4drop(s);
  document.getElementById("RC4drop").value = RC4drop;
  const base64 = hash_base64(s);
  document.getElementById("base64").value = base64;
  const latin1 = hash_latin1(s);
  document.getElementById("latin1").value = latin1;
  const hex = hash_hex(s);
  document.getElementById("hex").value = hex;
};
