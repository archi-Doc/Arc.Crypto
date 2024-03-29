﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;

namespace Arc.Crypto;

/// <summary>
/// Represents a collection of utf-16 key (ReadOnlySpan&lt;char&gt;) and value pairs.
/// </summary>
/// <typeparam name="TValue">The type of value.</typeparam>
public class Utf16Hashtable<TValue>
{
    private static uint CalculateCapacity(uint collectionSize)
    {
        collectionSize *= 2;
        uint capacity = 1;
        while (capacity < collectionSize)
        {
            capacity <<= 1;
        }

        if (capacity < 8)
        {
            return 8;
        }

        return capacity;
    }

    public Utf16Hashtable(uint capacity = 4)
    {
        var size = CalculateCapacity(capacity);
        this.hashTable = new Item[size];
    }

    public TValue[] ToArray()
    {
        lock (this.cs)
        {
            var table = this.hashTable;
            var array = new TValue[this.numberOfItems];

            var n = 0;
            for (var i = 0; i < table.Length; i++)
            {
                if (table[i] is { } item)
                {
                    array[n++] = item.Value;
                    if (n >= this.numberOfItems)
                    {
                        break;
                    }
                }
            }

            return array;
        }
    }

    public bool TryAdd(ReadOnlySpan<char> key, TValue value)
    {
        lock (this.cs)
        {
            bool successAdd;

            if ((this.numberOfItems * 2) > this.hashTable.Length)
            {// rehash
                this.RebuildTable();
            }

            // add entry(insert last is thread safe for read)
            successAdd = this.AddKeyValue(key, value);

            if (successAdd)
            {
                this.numberOfItems++;
            }

            return successAdd;
        }
    }

    public bool TryAdd(char[] key, TValue value)
    {
        lock (this.cs)
        {
            bool successAdd;

            if ((this.numberOfItems * 2) > this.hashTable.Length)
            {// rehash
                this.RebuildTable();
            }

            // add entry(insert last is thread safe for read)
            successAdd = this.AddKeyValue(key, value);

            if (successAdd)
            {
                this.numberOfItems++;
            }

            return successAdd;
        }
    }

    public bool TryGetValue(ReadOnlySpan<char> key, [MaybeNullWhen(false)] out TValue value)
    {
        var table = this.hashTable;
        var hash = unchecked((int)XxHash3.Hash64(key));
        var item = table[hash & (table.Length - 1)];

        while (item != null)
        {
            if (key.SequenceEqual(item.Key) == true)
            { // Identical. alternative: (key == item.Key).
                value = item.Value;
                return true;
            }

            item = item.Next;
        }

        value = default;
        return false;
    }

    public void Clear()
    {
        lock (this.cs)
        {
            for (var n = 0; n < this.hashTable.Length; n++)
            {
                Volatile.Write(ref this.hashTable[n], null);
            }
        }
    }

    private void RebuildTable()
    {
        var nextCapacity = this.hashTable.Length * 2;
        var nextTable = new Item[nextCapacity];
        for (var i = 0; i < this.hashTable.Length; i++)
        {
            var e = this.hashTable[i];
            while (e != null)
            {
                var newItem = new Item(e.Key, e.Value, e.Hash);
                this.AddItem(nextTable, newItem);
                e = e.Next;
            }
        }

        // replace field(threadsafe for read)
        Volatile.Write(ref this.hashTable, nextTable);
    }

    private bool AddItem(Item[] table, Item item)
    { // lock(cs) required.
        var h = item.Hash & (table.Length - 1);

        if (table[h] == null)
        {
            Volatile.Write(ref table[h], item);
        }
        else
        {
            var i = table[h];
            while (true)
            {
                if (i.Key.SequenceEqual(item.Key) == true)
                {// Identical
                    return false;
                }

                if (i.Next == null)
                { // Last item.
                    break;
                }

                i = i.Next;
            }

            Volatile.Write(ref i.Next, item);
        }

        return true;
    }

    private bool AddKeyValue(ReadOnlySpan<char> key, TValue value)
    { // lock(cs) required.
        var table = this.hashTable;
        var hash = unchecked((int)XxHash3.Hash64(key));
        var h = hash & (table.Length - 1);

        if (table[h] == null)
        {
            var item = new Item(key.ToArray(), value, hash);
            Volatile.Write(ref table[h], item);
        }
        else
        {
            var i = table[h]!;
            while (true)
            {
                if (key.SequenceEqual(i.Key) == true)
                {// Identical
                    return false;
                }

                if (i.Next == null)
                { // Last item.
                    break;
                }

                i = i.Next;
            }

            var item = new Item(key.ToArray(), value, hash);
            Volatile.Write(ref i.Next, item);
        }

        return true;
    }

    private bool AddKeyValue(char[] key, TValue value)
    { // lock(cs) required.
        var table = this.hashTable;
        var hash = unchecked((int)XxHash3.Hash64(key));
        var h = hash & (table.Length - 1);

        if (table[h] == null)
        {
            var item = new Item(key, value, hash);
            Volatile.Write(ref table[h], item);
        }
        else
        {
            var i = table[h]!;
            while (true)
            {
                if (key.SequenceEqual(i.Key) == true)
                {// Identical
                    return false;
                }

                if (i.Next == null)
                { // Last item.
                    break;
                }

                i = i.Next;
            }

            var item = new Item(key, value, hash);
            Volatile.Write(ref i.Next, item);
        }

        return true;
    }

    private readonly object cs = new object();
    private Item?[] hashTable;
    private uint numberOfItems;

    internal class Item
    {
#pragma warning disable SA1401
        public char[] Key;
        public TValue Value;
        public int Hash;
        public Item? Next;
#pragma warning restore SA1401

        public Item(char[] key, TValue value, int hash)
        {
            this.Key = key;
            this.Value = value;
            this.Hash = hash;
        }
    }
}
