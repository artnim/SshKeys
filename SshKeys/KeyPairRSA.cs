using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SshKeys
{
    public class KeyPairRSA
    {
        private RSAParameters _keyparams;

        private byte[] _passphrase;

        private byte[] _iv;

        private byte[] _key;

        private const string BEGIN = "-----BEGIN RSA PRIVATE KEY-----";

        private const string END = "-----END RSA PRIVATE KEY-----";

        private static string[] _header = { "Proc-Type: 4,ENCRYPTED", "DEK-Info: DES-EDE3-CBC,{0}" };

        private string _amoredPrivateKey;

        private byte[] _privateKey;

        public KeyPairRSA(int keysize = 1024, string passphrase = null)
        {
            var rsa = new RSACryptoServiceProvider(keysize);
            _keyparams = rsa.ExportParameters(true);
            _passphrase = string.IsNullOrEmpty(passphrase) ? null : Encoding.Default.GetBytes(passphrase);
        }

        public byte[] Key
        {
            get
            {
                return _key;
            }
        }

        public byte[] Iv
        {
            get 
            {
                if (null != _iv)
                {
                    return _iv;
                }

                _iv = new byte[8];

                var rng = new RNGCryptoServiceProvider();
                rng.GetBytes(_iv);

                return _iv;
            }
        }

        public byte[] Passphrase
        {
            get { return _passphrase; }
            set
            {
                _passphrase = value;

                if (null == value)
                {
                    _key = null;
                    _iv = null;
                    return;
                }

                _key = new byte[24];
                byte[] tmp = null;

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    while (stream.Length < 24)
                    {
                        using (var md5 = new MD5CryptoServiceProvider())
                        {
                            using (var cs = new CryptoStream(Stream.Null, md5, CryptoStreamMode.Write))
                            {
                                if (tmp != null)
                                {
                                    cs.Write(tmp, 0, tmp.Length);
                                }

                                cs.Write(_passphrase, 0, _passphrase.Length);
                                cs.Write(Iv, 0, Iv.Length);
                            }

                            tmp = md5.Hash;
                            writer.Write(tmp);
                        }
                    }

                    Array.Copy(stream.GetBuffer(), 0, _key, 0, _key.Length);
                }
            }
        }

        public byte[] PrivateKey
        {
            get
            {
                if (_privateKey != null) return _privateKey;
                
                _privateKey = GetPrivateKey();

                return _privateKey;

            }
        }

        private byte[] GetPrivateKey()
        {
            var asnWriter = new Asn1Writer(0x800);
            asnWriter.WriteInt(new byte[] {0x00});
            asnWriter.WriteInt(_keyparams.Modulus);
            asnWriter.WriteInt(_keyparams.Exponent);
            asnWriter.WriteInt(_keyparams.D);
            asnWriter.WriteInt(_keyparams.P);
            asnWriter.WriteInt(_keyparams.Q);
            asnWriter.WriteInt(_keyparams.DP);
            asnWriter.WriteInt(_keyparams.InverseQ);

            return asnWriter.SequenceBytes;
        }

        public string AmoredPrivateKey
        {
            get
            {
                if (_amoredPrivateKey != null) return _amoredPrivateKey;

                _amoredPrivateKey = GetAmoredPrivateKey();

                return _amoredPrivateKey;
            }
        }

        private string GetAmoredPrivateKey()
        {
            using (var writer = new StringWriter())
            {
                writer.WriteLine(BEGIN);

                var prv = Convert.ToBase64String(PrivateKey);

                var lines = string.Join(Environment.NewLine, Enumerable.Range(0, prv.Length / 64 + 1).Select(i =>
                {
                    var position = i * 64;
                    var length = prv.Length - position > 64 ? 64 : prv.Length - position;

                    return prv.Substring(position, length);
                }));

                writer.WriteLine(lines);

                writer.WriteLine(END);
                writer.Flush();

                _amoredPrivateKey = writer.ToString();
            }

            return _amoredPrivateKey;
        }
    }
}
