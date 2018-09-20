using Neo.Lux.Utils;
using Neo.VM;
using System.Collections.Generic;
using System.Linq;

namespace Neo.Emulation
{
    /// <summary>
    /// Implementation of <see cref="IScriptTable"/> interface
    /// </summary>
    public class ScriptTable : IScriptTable
    {
        private Dictionary<string, byte[]> scripts = null;

        public ScriptTable()
        {
            scripts = new Dictionary<string, byte[]>();
        }

        public void AddScript(string address, byte[] script)
        {
            AddScript(address.AddressToScriptHash(), script);
        }

        public void AddScript(byte[] script_hash, byte[] script)
        {
            scripts.Add(script_hash.Reverse().ToHexString(), script);
        }

        public byte[] GetScript(byte[] reverse_script_hash)
        {
            return scripts[reverse_script_hash.ToHexString()];
        }
    }
}
