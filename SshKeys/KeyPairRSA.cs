using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SshKeys
{
    public class KeyPairRSA
    {
        private RSAParameters _keyparams;

        private byte[] _passphrase;

        private byte[] _iv;

        public KeyPairRSA(int keysize = 1024, string passphrase = null)
        {
            var rsa = new RSACryptoServiceProvider(keysize);
            _keyparams = rsa.ExportParameters(true);
            _passphrase = string.IsNullOrEmpty(passphrase) ? null : Encoding.Default.GetBytes(passphrase);
        }

        public byte[] Key
        {
            [MethodImpl(MethodImplOptions.Synchronized)] get
            {
                byte[] key = new byte[24];
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

                    Array.Copy(stream.GetBuffer(), 0, key, 0, key.Length);
                }

                return key;
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
    }
}
