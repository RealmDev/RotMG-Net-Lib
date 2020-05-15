using System;
using System.Text;

namespace RotMG_Net_Lib.Crypto
{
    public class RC4
    {
        private static readonly int STATE_LENGTH = 256;

        private byte[] engineState;
        private int x;
        private int y;
        private byte[] workingKey;
        
        public RC4(string key) : this(HexStringToBytes(key))
        {
        }

        private RC4(byte[] key)
        {
            workingKey = key;
            SetKey(workingKey);
        }

        public void Cipher(byte[] packet, int slice)
        {
            ProcessBytes(packet, slice, packet.Length - slice, packet, slice);
        }

        public void Reset()
        {
            SetKey(workingKey);
        }

        private void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            for (int i = 0; i < length; i++)
            {
                x = (x + 1) & 0xff;
                y = (engineState[x] + y) & 0xff;

                byte tmp = engineState[x];
                engineState[x] = engineState[y];
                engineState[y] = tmp;

                output[i + outOff] = (byte) (input[i + inOff]
                                             ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
            }
        }

        private void SetKey(byte[] keyBytes)
        {
            workingKey = keyBytes;
            x = y = 0;

            if (engineState == null)
                engineState = new byte[STATE_LENGTH];

            for (int i = 0; i < STATE_LENGTH; i++)
                engineState[i] = (byte) i;

            int i1 = 0, i2 = 0;

            for (int i = 0; i < STATE_LENGTH; i++)
            {
                i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
                byte tmp = engineState[i];
                engineState[i] = engineState[i2];
                engineState[i2] = tmp;
                i1 = (i1 + 1) % keyBytes.Length;
            }
        }

        private static byte[] HexStringToBytes(string key)
        {
            if (key.Length % 2 != 0)
                throw new ArgumentException("Invalid hex string!");

            byte[] bytes = new byte[key.Length / 2];
            char[] c = key.ToCharArray();
            for (int i = 0; i < c.Length; i += 2)
            {
                StringBuilder sb = new StringBuilder(2).Append(c[i]).Append(c[(i + 1)]);
                int j = Convert.ToInt32(sb.ToString(), 16);
                bytes[(i / 2)] = (byte) j;
            }

            return bytes;
        }
    }
}