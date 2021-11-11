// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

#pragma warning disable SA1649 // File name should match first type name

namespace Arc.Crypto;

/// <summary>
/// String extensions.
/// </summary>
public static class String
{
    /// <summary>
    /// Convert the hex string to a byte array. Characters other than 0-9 a-f A-F will be ignored.
    /// </summary>
    /// <param name="hex">The hex string.</param>
    /// <returns>A byte array.</returns>
    public static byte[] HexToByte(this string hex)
    {
        ReadOnlySpan<char> c = hex;
        var maxLength = (c.Length / 2) + 1;
        Span<byte> buffer = maxLength > 1024 ? new byte[maxLength] : stackalloc byte[maxLength];
        var bufferPosition = 0;

        bool flag = false;
        byte value, store;
        store = 0;
        for (var n = 0; n < c.Length; n++)
        {
            if (c[n] == '0')
            {
                if (n + 1 < c.Length && (c[n + 1] == 'x' || c[n + 1] == 'X'))
                { // skip "0x"
                    n++;
                    continue;
                }

                // '0'
                value = 0;
            }
            else if (c[n] > '0' && c[n] <= '9')
            {
                value = (byte)(c[n] - '0');
            }
            else if (c[n] >= 'a' && c[n] <= 'f')
            {
                value = (byte)(c[n] - 'a' + 10);
            }
            else if (c[n] >= 'A' && c[n] <= 'F')
            {
                value = (byte)(c[n] - 'A' + 10);
            }
            else
            {
                continue;
            }

            if (flag == false)
            {
                store = value;
                flag = true;
            }
            else
            {
                buffer[bufferPosition++] = (byte)((store << 4) | value);
                flag = false;
            }
        }

        if (flag == true)
        {
            buffer[bufferPosition++] = store;
        }

        return buffer.Slice(0, bufferPosition).ToArray();
    }
}
