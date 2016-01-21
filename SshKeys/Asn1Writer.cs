using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;


namespace SshKeys
{
    public class Asn1Writer : IDisposable
    {
        private bool _disposed = false;

        private MemoryStream _stream;

        private BinaryWriter _writer;

        private long _count;

        private byte[] _data;

        public Asn1Writer(int initialSize)
        {
            _stream = new MemoryStream(initialSize);
            _writer = new BinaryWriter(_stream);
        }


        public byte[] SequenceBytes
        {
            get
            {
                if (_stream.Length == _count)
                {
                    return _data;
                }

                using (var stream = new MemoryStream((int) _stream.Length + 0x10))
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write((byte) 0x30);
                    var data = new byte[_stream.Length];
                    Array.Copy(_stream.GetBuffer(), 0, data, 0, data.Length);
                    writer.WriteBytes(data);

                    _data = new byte[stream.Length];
                    Array.Copy(stream.GetBuffer(), 0, _data, 0, (int) stream.Length);

                    _count = _stream.Length;

                    return _data;
                }
            }
        }

        public void WriteInt(byte[] data)
        {
            _writer.Write((byte) 0x02);
            _writer.WriteBytes(data);
        }

        internal static byte[] GetLength(byte[] data)
        {
            var lengthBytes = new List<byte>();

            for (var length = data.Length + (data[0] < 0x80 ? 0 : 1); length > 0; length >>= 8)
            {
                lengthBytes.Add((byte) (length & 0xff));
            }

            if (lengthBytes.Count == 1 && lengthBytes.Last() < 0x80)
            {
                return lengthBytes.ToArray();
            }

            lengthBytes.Add((byte)(0x80 | lengthBytes.Count));
            lengthBytes.Reverse();

            return lengthBytes.ToArray();
        }

        ~Asn1Writer()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _writer.Close();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}