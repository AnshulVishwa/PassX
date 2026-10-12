import { useEffect, useState } from "react";
import { useParams } from "react-router";
import { db } from "../../firebase.config";
import { collection, getDocs, addDoc } from "firebase/firestore";
import CryptoJs from "crypto-js";

interface StoredPassword {
  id?: string;
  name: string;
  passFor: string;
  pass: string;
  isDecrypted?: boolean;
}

export default function Home() {
  const params = useParams<{ name: string }>();
  const [passwords, setPasswords] = useState<StoredPassword[]>([]);
  const [passFor, setPassFor] = useState("");
  const [pass, setPass] = useState("");
  const [key, setKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchPasswords = async () => {
    try {
      const snap = await getDocs(collection(db, "pwd"));
      const items = snap.docs.filter(
        (doc) => (doc.data() as Omit<StoredPassword, "id">).name === params.name
      );
      setPasswords(
        items.map((doc) => ({
          id: doc.id,
          ...(doc.data() as Omit<StoredPassword, "id">),
          isDecrypted: false,
        }))
      );
    } catch (err) {
      console.error("Error fetching passwords:", err);
    }
  };

  useEffect(() => {
    fetchPasswords();
  }, [params.name]);

  const handleAddPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passFor.trim() || !pass.trim()) return;

    if (!key.trim()) {
      alert("Please provide an encryption key so your password can be encrypted securely.");
      return;
    }

    const cipherText = CryptoJs.AES.encrypt(pass, key).toString();

    setLoading(true);
    try {
      await addDoc(collection(db, "pwd"), {
        name: params.name,
        passFor: passFor.trim(),
        pass: cipherText,
      });
      setPassFor("");
      setPass("");
      await fetchPasswords();
    } catch (err) {
      console.error("Error adding password:", err);
      alert("Failed to save password. Check your connection or Firebase config.");
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = (p: StoredPassword) => {
    let secretKey = key.trim();
    if (!secretKey) {
      const promptKey = window.prompt(`Enter decryption key for "${p.passFor}":`);
      if (!promptKey) return;
      secretKey = promptKey.trim();
    }

    try {
      const bytes = CryptoJs.AES.decrypt(p.pass, secretKey);
      const decryptedPass = bytes.toString(CryptoJs.enc.Utf8);

      if (!decryptedPass) {
        alert("Incorrect key or failed to decrypt!");
        return;
      }

      setPasswords((prev) =>
        prev.map((item) =>
          item.id === p.id
            ? { ...item, pass: decryptedPass, isDecrypted: true }
            : item
        )
      );
    } catch {
      alert("Failed to decrypt with this key!");
    }
  };

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Fallback if clipboard API is restricted
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const displayName = params.name ? params.name.toLowerCase() : "user";

  return (
    <div className="min-h-screen bg-[#0f0f11] text-neutral-200 px-4 py-8 sm:py-12 flex flex-col items-center">
      <div className="w-full max-w-lg flex flex-col gap-6">
        
        {/* Header */}
        <header className="flex items-center justify-between border-b border-neutral-800 pb-4">
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-white">PassX</h1>
            <p className="text-xs text-neutral-400">Vault for {displayName}</p>
          </div>
          <span className="text-xs font-mono text-neutral-400 bg-neutral-900 border border-neutral-800 px-2.5 py-1 rounded-md">
            {passwords.length} {passwords.length === 1 ? "entry" : "entries"}
          </span>
        </header>

        {/* Add Password Form */}
        <section className="bg-neutral-900/60 border border-neutral-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Add Password</h2>

          <form onSubmit={handleAddPassword} className="flex flex-col gap-3.5">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-neutral-400">Account / Service</label>
              <input
                type="text"
                value={passFor}
                onChange={(e) => setPassFor(e.target.value)}
                placeholder="e.g. GitHub"
                required
                className="w-full bg-[#141416] border border-neutral-800 rounded-lg px-3 py-2 text-sm text-white placeholder-neutral-600 focus:border-neutral-500 focus:outline-none transition-colors"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs text-neutral-400">Secret Key</label>
              <input
                type="password"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="Key to encrypt and decrypt"
                required
                className="w-full bg-[#141416] border border-neutral-800 rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-neutral-600 focus:border-neutral-500 focus:outline-none transition-colors"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs text-neutral-400">Password</label>
              <div className="relative">
                <input
                  type={showPass ? "text" : "password"}
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder="Enter password"
                  required
                  className="w-full bg-[#141416] border border-neutral-800 rounded-lg px-3 py-2 pr-14 text-sm text-white placeholder-neutral-600 focus:border-neutral-500 focus:outline-none transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-neutral-400 hover:text-white px-2 py-0.5 rounded cursor-pointer"
                >
                  {showPass ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="mt-1 w-full bg-white hover:bg-neutral-200 text-black font-medium py-2 rounded-lg text-sm transition-colors disabled:opacity-50 cursor-pointer"
            >
              {loading ? "Saving..." : "Save Password"}
            </button>
          </form>
        </section>

        {/* Saved Passwords */}
        <section className="flex flex-col gap-3">
          <h2 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider px-0.5">
            Saved Passwords
          </h2>

          {passwords.length === 0 ? (
            <div className="text-center py-10 border border-neutral-800/80 rounded-xl text-xs text-neutral-500">
              No passwords saved yet.
            </div>
          ) : (
            <div className="flex flex-col gap-2.5">
              {passwords.map((p) => (
                <div
                  key={p.id}
                  className="bg-neutral-900/60 border border-neutral-800 rounded-xl p-4 flex flex-col gap-2.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-white">{p.passFor}</span>
                    <span className="text-[11px] font-mono text-neutral-400">
                      {p.isDecrypted ? "Decrypted" : "Encrypted"}
                    </span>
                  </div>

                  <div className="bg-[#141416] border border-neutral-800/80 rounded-lg px-3 py-2 font-mono text-xs text-neutral-300 break-all select-all">
                    {p.pass}
                  </div>

                  <div className="flex items-center justify-end gap-2 pt-0.5">
                    <button
                      type="button"
                      onClick={() => handleCopy(p.id || "", p.pass)}
                      className="text-xs text-neutral-300 hover:text-white px-2.5 py-1 rounded border border-neutral-800 hover:border-neutral-700 transition-colors cursor-pointer"
                    >
                      {copiedId === p.id ? "Copied" : "Copy"}
                    </button>

                    {!p.isDecrypted && (
                      <button
                        type="button"
                        onClick={() => handleDecrypt(p)}
                        className="text-xs text-white px-2.5 py-1 rounded bg-neutral-800 hover:bg-neutral-700 border border-neutral-700/60 transition-colors cursor-pointer"
                      >
                        Decrypt
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

      </div>
    </div>
  );
}
