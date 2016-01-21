using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
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

        private byte[] _publicKey;

        public KeyPairRSA(int keysize = 1024, string passphrase = null)
        {
            var rsa = new RSACryptoServiceProvider(keysize);
            _keyparams = rsa.ExportParameters(true);
            Passphrase = string.IsNullOrEmpty(passphrase) ? null : Encoding.Default.GetBytes(passphrase);
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

                var asnWriter = new Asn1Writer(0x800);
                asnWriter.WriteInt(new byte[] {0x00}, _keyparams.Modulus, _keyparams.Exponent, _keyparams.D, _keyparams.P, _keyparams.Q, _keyparams.DP, _keyparams.DQ, _keyparams.InverseQ);

                _privateKey = asnWriter.SequenceBytes;

                return _privateKey;

            }
        }

        public string AmoredPrivateKey
        {
            get
            {
                if (_amoredPrivateKey != null) return _amoredPrivateKey;

                using (var writer = new StringWriter())
                {
                    writer.WriteLine(BEGIN);

                    if (null != _passphrase)
                    {
                        writer.WriteLine(_header[0]);
                        writer.WriteLine(_header[1], string.Join(null, Iv.Select(b => b.ToString("X"))));
                        writer.WriteLine();
                    }

                    var prv = Convert.ToBase64String(EncryptedPrivateKey);

                    var lines = string.Join(Environment.NewLine, Enumerable.Range(0, prv.Length / 64 + (prv.Length % 64 == 0 ? 0 : 1)).Select(i =>
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

        public byte[] EncryptedPrivateKey
        {
            [MethodImpl(MethodImplOptions.Synchronized)]
            get
            {
                if (null == _passphrase) return PrivateKey;

                var tripleDes = new TripleDESCryptoServiceProvider() {Mode = CipherMode.CBC, Padding = PaddingMode.None};
                var encryptor = tripleDes.CreateEncryptor(Key, Iv);


                var clear = new byte[PrivateKey.Length % 24 != 0 ? (PrivateKey.Length / 24 + 1) * 24 : PrivateKey.Length];
                Array.Copy(PrivateKey, 0, clear, 0, PrivateKey.Length);
                var cipher = new byte[clear.Length];

                encryptor.TransformBlock(clear, 0, clear.Length, cipher, 0);

                return cipher;
            }
        }

        private void WriteBytes(BinaryWriter writer, params byte[][] data)
        {
            foreach (var d in data)
            {
                var length = data.Length + (d[0] < 0x80 ? 0 : 1);
                writer.Write(IPAddress.HostToNetworkOrder(length));

                if (d[0] > 0x7f)
                {
                    writer.Write((byte) 0x00);
                }

                writer.Write(d);
            }
        }

        public byte[] PublicKey
        {
            get
            {
                if (_publicKey != null) return _publicKey;
                
                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WriteBytes(writer, Encoding.Default.GetBytes("ssh-rsa"), _keyparams.Exponent, _keyparams.Modulus);
                    writer.Flush();

                    _publicKey = new byte[stream.Length];
                    Array.Copy(stream.GetBuffer(), 0, _publicKey, 0, _publicKey.Length);
                }

                return _publicKey;
            }
        }

        public string Base64PublicKey
        {
            get { return string.Format("ssh-rsa {0}", Convert.ToBase64String(PublicKey)); }
        }
    }
}
