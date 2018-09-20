using Neo.Emulation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Neo.VM.Types;
using NEO_Emulator.VM;
using VMArray = Neo.VM.Types.Array;
using VMBoolean = Neo.VM.Types.Boolean;

namespace Neo.VM
{
    public class InteropCall
    {
        public string name;
        public Func<ExecutionEngine, bool> handler;
        public decimal gasCost;
    }

    public class InteropService
    {
        public const decimal defaultGasCost = 0.001m;

        private Dictionary<string, InteropCall> dictionary = new Dictionary<string, InteropCall>();

        public IEnumerable<InteropCall> Calls => dictionary.Values;

        public InteropService()
        {
            Register("System.ExecutionEngine.GetScriptContainer", GetScriptContainer, defaultGasCost);
            Register("System.ExecutionEngine.GetExecutingScriptHash", GetExecutingScriptHash, defaultGasCost);
            Register("System.ExecutionEngine.GetCallingScriptHash", GetCallingScriptHash, defaultGasCost);
            Register("System.ExecutionEngine.GetEntryScriptHash", GetEntryScriptHash, defaultGasCost);

            Register("Neo.Runtime.Serialize", Runtime_Serialize, defaultGasCost);
            Register("Neo.Runtime.Deserialize", Runtime_Deserialize, defaultGasCost);

            var assembly = typeof(VMUtils).Assembly;
            var methods = assembly.GetTypes()
                                  .SelectMany(t => t.GetMethods())
                                  .Where(m => m.GetCustomAttributes(typeof(SyscallAttribute), false).Length > 0)
                                  .ToArray();

            foreach (var method in methods)
            {
                var attr = (SyscallAttribute)method.GetCustomAttributes(typeof(SyscallAttribute), false).FirstOrDefault();

                this.Register(attr.Method, (engine) => { return (bool)method.Invoke(null, new object[] { engine }); }, attr.gasCost);
            }
        }

        public InteropCall FindCall(string method)
        {
            if (!dictionary.ContainsKey(method)) return null;
            return dictionary[method];
        }

        public void Register(string method, Func<ExecutionEngine, bool> handler, decimal gasCost)
        {
            var call = new InteropCall();
            call.handler = handler;
            call.gasCost = gasCost;
            call.name = method;
            dictionary[method] = call;
        }

        internal bool Invoke(string method, ExecutionEngine engine)
        {
            if (!dictionary.ContainsKey(method)) return false;
            return dictionary[method].handler(engine);
        }

        private static bool GetScriptContainer(ExecutionEngine engine)
        {
            engine.EvaluationStack.Push(StackItem.FromInterface(engine.ScriptContainer));
            return true;
        }

        private static bool GetExecutingScriptHash(ExecutionEngine engine)
        {
            engine.EvaluationStack.Push(engine.CurrentContext.ScriptHash.ToArray());
            return true;
        }

        private static bool GetCallingScriptHash(ExecutionEngine engine)
        {
            engine.EvaluationStack.Push(engine.CallingContext.ScriptHash.ToArray());
            return true;
        }

        private static bool GetEntryScriptHash(ExecutionEngine engine)
        {
            engine.EvaluationStack.Push(engine.EntryContext.ScriptHash.ToArray());
            return true;
        }

        private void SerializeStackItem(StackItem item, BinaryWriter writer)
        {
            List<StackItem> serialized = new List<StackItem>();
            Stack<StackItem> unserialized = new Stack<StackItem>();
            unserialized.Push(item);
            while (unserialized.Count > 0)
            {
                item = unserialized.Pop();
                switch (item)
                {
                    case ByteArray _:
                        writer.Write((byte)StackItemType.ByteArray);
                        writer.WriteVarBytes(item.GetByteArray());
                        break;
                    case VMBoolean _:
                        writer.Write((byte)StackItemType.Boolean);
                        writer.Write(item.GetBoolean());
                        break;
                    case Integer _:
                        writer.Write((byte)StackItemType.Integer);
                        writer.WriteVarBytes(item.GetByteArray());
                        break;
                    case InteropInterface _:
                        throw new NotSupportedException();
                    case VMArray array:
                        if (serialized.Any(p => ReferenceEquals(p, array)))
                            throw new NotSupportedException();
                        serialized.Add(array);
                        if (array is Struct)
                            writer.Write((byte)StackItemType.Struct);
                        else
                            writer.Write((byte)StackItemType.Array);
                        writer.WriteVarInt(array.Count);
                        for (int i = array.Count - 1; i >= 0; i--)
                            unserialized.Push(array[i]);
                        break;
                    case Map map:
                        if (serialized.Any(p => ReferenceEquals(p, map)))
                            throw new NotSupportedException();
                        serialized.Add(map);
                        writer.Write((byte)StackItemType.Map);
                        writer.WriteVarInt(map.Count);
                        foreach (var pair in map.Reverse())
                        {
                            unserialized.Push(pair.Value);
                            unserialized.Push(pair.Key);
                        }
                        break;
                }
            }
        }

        protected bool Runtime_Serialize(ExecutionEngine engine)
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                try
                {
                    SerializeStackItem(engine.EvaluationStack.Pop(), writer);
                }
                catch (NotSupportedException)
                {
                    return false;
                }
                writer.Flush();
                if (ms.Length > ExecutionEngine.MaxItemSize)
                    return false;
                engine.EvaluationStack.Push(ms.ToArray());
            }
            return true;
        }

        private StackItem DeserializeStackItem(BinaryReader reader)
        {
            Stack<StackItem> deserialized = new Stack<StackItem>();
            int undeserialized = 1;
            while (undeserialized-- > 0)
            {
                StackItemType type = (StackItemType)reader.ReadByte();
                switch (type)
                {
                    case StackItemType.ByteArray:
                        deserialized.Push(new ByteArray(reader.ReadVarBytes()));
                        break;
                    case StackItemType.Boolean:
                        deserialized.Push(new VMBoolean(reader.ReadBoolean()));
                        break;
                    case StackItemType.Integer:
                        deserialized.Push(new Integer(new BigInteger(reader.ReadVarBytes())));
                        break;
                    case StackItemType.Array:
                    case StackItemType.Struct:
                        {
                            int count = (int)reader.ReadVarInt(ExecutionEngine.MaxArraySize);
                            deserialized.Push(new ContainerPlaceholder
                            {
                                Type = type,
                                ElementCount = count
                            });
                            undeserialized += count;
                        }
                        break;
                    case StackItemType.Map:
                        {
                            int count = (int)reader.ReadVarInt(ExecutionEngine.MaxArraySize);
                            deserialized.Push(new ContainerPlaceholder
                            {
                                Type = type,
                                ElementCount = count
                            });
                            undeserialized += count * 2;
                        }
                        break;
                    default:
                        throw new FormatException();
                }
            }
            Stack<StackItem> stack_temp = new Stack<StackItem>();
            while (deserialized.Count > 0)
            {
                StackItem item = deserialized.Pop();
                if (item is ContainerPlaceholder placeholder)
                {
                    switch (placeholder.Type)
                    {
                        case StackItemType.Array:
                            VMArray array = new VMArray();
                            for (int i = 0; i < placeholder.ElementCount; i++)
                                array.Add(stack_temp.Pop());
                            item = array;
                            break;
                        case StackItemType.Struct:
                            Struct @struct = new Struct();
                            for (int i = 0; i < placeholder.ElementCount; i++)
                                @struct.Add(stack_temp.Pop());
                            item = @struct;
                            break;
                        case StackItemType.Map:
                            Map map = new Map();
                            for (int i = 0; i < placeholder.ElementCount; i++)
                            {
                                StackItem key = stack_temp.Pop();
                                StackItem value = stack_temp.Pop();
                                map.Add(key, value);
                            }
                            item = map;
                            break;
                    }
                }
                stack_temp.Push(item);
            }
            return stack_temp.Peek();
        }

        protected bool Runtime_Deserialize(ExecutionEngine engine)
        {
            byte[] data = engine.EvaluationStack.Pop().GetByteArray();
            using (MemoryStream ms = new MemoryStream(data, false))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                StackItem item;
                try
                {
                    item = DeserializeStackItem(reader);
                }
                catch (FormatException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }
                engine.EvaluationStack.Push(item);
            }
            return true;
        }
    }
}
