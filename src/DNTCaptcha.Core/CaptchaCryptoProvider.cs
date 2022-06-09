using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace DNTCaptcha.Core
{
    /// <summary>
    /// The default captcha protection provider
    /// </summary>
    public class CaptchaCryptoProvider : ICaptchaCryptoProvider
    {
        private readonly byte[] _keyBytes;

        /// <summary>
        /// The default captcha protection provider
        /// </summary>
        public CaptchaCryptoProvider(IOptions<DNTCaptchaOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            _keyBytes = getDesKey(options.Value.EncryptionKey);
        }

        /// <summary>
        /// Creates the hash of the message
        /// </summary>
        public (string HashString, byte[] HashBytes) Hash(string inputText)
        {
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(inputText));
                return (Encoding.UTF8.GetString(hash), hash);
            }
        }

        /// <summary>
        /// Decrypts the message
        /// </summary>
        public string? Decrypt(string inputText, bool ecb = false)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                throw new ArgumentNullException(nameof(inputText));
            }

            var inputBytes = WebEncoders.Base64UrlDecode(inputText);
            var bytes = ecb ? decryptEcb(inputBytes) : decrypt(inputBytes);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Encrypts the message
        /// </summary>
        public string Encrypt(string inputText, bool ecb = false)
        {
            if (string.IsNullOrWhiteSpace(inputText))
            {
                throw new ArgumentNullException(nameof(inputText));
            }

            var inputBytes = Encoding.UTF8.GetBytes(inputText);
            var bytes = ecb ? encryptEcb(inputBytes) : encrypt(inputBytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        private byte[] encrypt(byte[] data)
        {
            using (var des = new TripleDESCryptoServiceProvider
                   {
                       Key = _keyBytes,
                       Mode = CipherMode.CBC,
                       Padding = PaddingMode.PKCS7
                   })
            {
                using var encryptor = des.CreateEncryptor();
                using var cipherStream = new MemoryStream();
                using (var cryptoStream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write))
                using (var binaryWriter = new BinaryWriter(cryptoStream))
                {
                    // prepend IV to data
                    cipherStream.Write(des.IV); // This is an auto-generated random key
                    binaryWriter.Write(data);
                    cryptoStream.FlushFinalBlock();
                }
                return cipherStream.ToArray();
            }
        }

        private byte[] encryptEcb(byte[] data)
        {
            using (var des = new TripleDESCryptoServiceProvider
                   {
                       Key = _keyBytes,
                       Mode = CipherMode.ECB,
                       Padding = PaddingMode.PKCS7
                   })
            {
                using var encryptor = des.CreateEncryptor();
                using var cipherStream = new MemoryStream();
                using (var cryptoStream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write))
                using (var binaryWriter = new BinaryWriter(cryptoStream))
                {
                    binaryWriter.Write(data);
                    cryptoStream.FlushFinalBlock();
                }
                return cipherStream.ToArray();
            }
        }

        private byte[] decrypt(byte[] data)
        {
            using (var des = new TripleDESCryptoServiceProvider
            {
                Key = _keyBytes,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                var iv = new byte[8]; // 3DES-IV is always 8 bytes/64 bits because block size is always 64 bits
                Array.Copy(data, 0, iv, 0, iv.Length);

                using var ms = new MemoryStream();
                using (var decryptor = new CryptoStream(ms, des.CreateDecryptor(_keyBytes, iv), CryptoStreamMode.Write))
                using (var binaryWriter = new BinaryWriter(decryptor))
                {
                    // decrypt cipher text from data, starting just past the IV
                    binaryWriter.Write(
                        data,
                        iv.Length,
                        data.Length - iv.Length
                    );
                }
                return ms.ToArray();
            }
        }

        private byte[] decryptEcb(byte[] data)
        {
            using (var des = new TripleDESCryptoServiceProvider
                   {
                       Key = _keyBytes,
                       Mode = CipherMode.ECB,
                       Padding = PaddingMode.PKCS7
                   })
            {
                var iv = new byte[8];
                using var ms = new MemoryStream();
                using (var decryptor = new CryptoStream(ms, des.CreateDecryptor(_keyBytes, iv), CryptoStreamMode.Write))
                using (var binaryWriter = new BinaryWriter(decryptor))
                {
                    binaryWriter.Write(data);
                }
                return ms.ToArray();
            }
        }

        private byte[] getDesKey(string? key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new InvalidOperationException("Please set the `options.WithEncryptionKey(...)`.");
            }
            // The key size of TripleDES is 168 bits, its len in byte is 24 Bytes (or 192 bits).
            // Last bit of each byte is not used (or used as version in some hardware).
            // Key len for TripleDES can also be 112 bits which is again stored in 128 bits or 16 bytes.
            return Hash(key).HashBytes.Take(24).ToArray();
        }
    }
}