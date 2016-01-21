using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SshKeys
{
    class KeyPairRSA
    {
        private RSAParameters _keyparams;

        KeyPairRSA(int keysize = 1024)
        {
            var rsa = new RSACryptoServiceProvider(keysize);
            _keyparams = rsa.ExportParameters(true);
        }
    }
}
