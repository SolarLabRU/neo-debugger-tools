﻿using Neo.VM;
using System;

namespace NEO_Emulator.VM
{
    public class ContainerPlaceholder : StackItem
    {
        public StackItemType Type;
        public int ElementCount;

        public override bool Equals(StackItem other)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetByteArray()
        {
            throw new NotSupportedException();
        }
    }
}
