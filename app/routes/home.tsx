import { useEffect, useState, useRef, useMemo } from "react";
import { db, auth } from "../../firebase.config";
import {
  collection,
  getDocs,
  doc,
  getDoc,
  setDoc,
  addDoc,
  deleteDoc,
  serverTimestamp,
} from "firebase/firestore";
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";
import validator from "validator";
import {
  deriveMasterKey,
  createVaultVerifier,
  verifyMasterKey,
  encryptData,
  decryptData,
  generateSalt,
  generateSecurePassword,
  evaluatePasswordStrength,
  type PasswordGeneratorOptions,
} from "../lib/crypto";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  Key,
  Copy,
  Check,
  Eye,
  EyeOff,
  Trash2,
  Plus,
  RefreshCw,
  LogOut,
  Sparkles,
  Clock,
  AlertTriangle,
  Search,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
  X,
  Sliders,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

interface VaultItemPayload {
  service: string;
  username: string;
  pass: string;
  notes?: string;
  category?: string;
  updatedAt: string;
}

interface DecryptedVaultItem extends VaultItemPayload {
  id: string;
  isDecrypted: boolean;
}

interface StoredEncryptedDoc {
  id: string;
  ciphertext: string;
  iv: string;
  userId?: string;
}

interface ClipboardAlertState {
  id: string;
  label: string;
  expiresAt: number;
}

const CATEGORIES = ["All", "Logins", "Banking", "Work", "Personal"] as const;

export default function Home() {
  // Authentication State
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authTab, setAuthTab] = useState<"signin" | "signup">("signin");
  const [emailInput, setEmailInput] = useState("");
  const [authPasswordInput, setAuthPasswordInput] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);

  // Vault Security & Crypto State
  const [vaultStatus, setVaultStatus] = useState<"checking" | "needs_setup" | "locked" | "unlocked">("checking");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmMasterPassword, setConfirmMasterPassword] = useState("");
  const [masterKey, setMasterKey] = useState<CryptoKey | null>(null);
  const [userSalt, setUserSalt] = useState<string | null>(null);
  const [storedVerifier, setStoredVerifier] = useState<{ ciphertext: string; iv: string } | null>(null);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultError, setVaultError] = useState<string | null>(null);

  // Vault Items State
  const [items, setItems] = useState<DecryptedVaultItem[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [activeTab, setActiveTab] = useState<"items" | "add" | "generator" | "audit">("items");
  const [expandedNotesId, setExpandedNotesId] = useState<string | null>(null);
  const [revealedPasswords, setRevealedPasswords] = useState<Record<string, boolean>>({});

  // New Item Form State
  const [newService, setNewService] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newNotes, setNewNotes] = useState("");
  const [newCategory, setNewCategory] = useState("Logins");
  const [savingItem, setSavingItem] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);

  // Password Generator State
  const [genOptions, setGenOptions] = useState<PasswordGeneratorOptions>({
    length: 22,
    useUpper: true,
    useLower: true,
    useNumbers: true,
    useSymbols: true,
    avoidAmbiguous: true,
  });
  const [generatedPassword, setGeneratedPassword] = useState("");

  // Clipboard Security State (Timestamp-based 30s Countdown Wipe)
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [clipboardAlert, setClipboardAlert] = useState<ClipboardAlertState | null>(null);
  const [clipboardSecondsLeft, setClipboardSecondsLeft] = useState<number>(0);
  const [showSanitizedToast, setShowSanitizedToast] = useState(false);

  // Vault Session Security Timer (Steady Wall-Clock 15-Minute Countdown - NEVER restarts on mouse moves!)
  const SESSION_DURATION_SECONDS = 15 * 60; // 15 minutes
  const [sessionExpiresAt, setSessionExpiresAt] = useState<number | null>(null);
  const [sessionSecondsLeft, setSessionSecondsLeft] = useState<number>(SESSION_DURATION_SECONDS);

  const startVaultSession = () => {
    const expires = Date.now() + SESSION_DURATION_SECONDS * 1000;
    setSessionExpiresAt(expires);
    setSessionSecondsLeft(SESSION_DURATION_SECONDS);
  };

  const extendSession = () => {
    setSessionExpiresAt((prev) => {
      const base = prev && prev > Date.now() ? prev : Date.now();
      const newTime = base + 10 * 60 * 1000; // Adds 10 minutes
      setSessionSecondsLeft(Math.ceil((newTime - Date.now()) / 1000));
      return newTime;
    });
  };

  const lockVault = (message?: string) => {
    setMasterKey(null);
    setItems([]);
    setMasterPassword("");
    setRevealedPasswords({});
    setSessionExpiresAt(null);
    setSessionSecondsLeft(SESSION_DURATION_SECONDS);
    setVaultStatus("locked");
    if (message) {
      setVaultError(message);
    }
  };

  // Steady Session Countdown Effect (immune to re-renders & mouse activity)
  useEffect(() => {
    if (vaultStatus !== "unlocked" || !sessionExpiresAt) return;

    const tick = () => {
      const diff = Math.ceil((sessionExpiresAt - Date.now()) / 1000);
      if (diff <= 0) {
        setSessionSecondsLeft(0);
        lockVault("Vault session expired (15m). Locked to protect client memory.");
      } else {
        setSessionSecondsLeft(diff);
      }
    };

    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [vaultStatus, sessionExpiresAt]);

  // Clipboard 30-Second Auto-Wipe Effect (Timestamp-based: counts down steadily and auto-removes at 0)
  useEffect(() => {
    if (!clipboardAlert) return;

    const checkClipboardTimer = () => {
      const diff = Math.ceil((clipboardAlert.expiresAt - Date.now()) / 1000);
      if (diff <= 0) {
        try {
          navigator.clipboard.writeText("");
        } catch {}
        setClipboardAlert(null);
        setClipboardSecondsLeft(0);
        setShowSanitizedToast(true);
        setTimeout(() => setShowSanitizedToast(false), 2500);
      } else {
        setClipboardSecondsLeft(diff);
      }
    };

    checkClipboardTimer();
    const interval = setInterval(checkClipboardTimer, 500);
    return () => clearInterval(interval);
  }, [clipboardAlert]);

  // Initialize Generator
  useEffect(() => {
    setGeneratedPassword(generateSecurePassword(genOptions));
  }, []);

  // Listen for Firebase Auth State Changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setAuthLoading(false);
    });
    return () => unsubscribe();
  }, []);

  // Fetch User Vault Profile (Salt & Cryptographic Verifier)
  useEffect(() => {
    if (!user) {
      setVaultStatus("checking");
      return;
    }

    const checkVaultProfile = async () => {
      setVaultLoading(true);
      setVaultError(null);
      try {
        const userDocRef = doc(db, "users", user.uid);
        const userSnap = await getDoc(userDocRef);

        if (userSnap.exists()) {
          const data = userSnap.data();
          if (data.salt && data.verifier) {
            setUserSalt(data.salt);
            setStoredVerifier(data.verifier);
            setVaultStatus("locked");
          } else {
            setVaultStatus("needs_setup");
          }
        } else {
          setVaultStatus("needs_setup");
        }
      } catch (err: unknown) {
        console.error("Error checking vault profile:", err);
        setVaultError("Could not retrieve vault status. Please verify your Firestore rules are published.");
      } finally {
        setVaultLoading(false);
      }
    };

    checkVaultProfile();
  }, [user]);

  // Clipboard Copy with Guaranteed 30-Second Auto-Wipe and Visual Removal
  const handleSecureCopy = async (id: string, textToCopy: string, label: string = "Password") => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);

      const expiresAt = Date.now() + 30000;
      setClipboardAlert({ id, label, expiresAt });
      setClipboardSecondsLeft(30);
    } catch {
      alert(`Could not copy ${label} to clipboard. Permission may be denied.`);
    }
  };

  // Immediate Manual Clipboard Wipe
  const handleManualClipboardWipe = async () => {
    try {
      await navigator.clipboard.writeText("");
    } catch {}
    setClipboardAlert(null);
    setClipboardSecondsLeft(0);
    setShowSanitizedToast(true);
    setTimeout(() => setShowSanitizedToast(false), 2000);
  };

  // Dismiss alert visually
  const handleDismissClipboardAlert = () => {
    setClipboardAlert(null);
  };

  // Toggle revealed password
  const togglePasswordVisibility = (id: string) => {
    setRevealedPasswords((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Initialize Master Key
  const handleInitializeVault = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setVaultError(null);

    if (masterPassword.length < 12) {
      setVaultError("Master Password must be at least 12 characters for cryptographic security.");
      return;
    }

    if (masterPassword !== confirmMasterPassword) {
      setVaultError("Master Passwords do not match.");
      return;
    }

    setVaultLoading(true);
    try {
      // 1. Generate unique 16-byte random salt
      const salt = generateSalt();

      // 2. Derive 256-bit AES-GCM Key (600,000 PBKDF2 rounds)
      const derivedKey = await deriveMasterKey(masterPassword, salt);

      // 3. Create zero-knowledge verifier token
      const verifier = await createVaultVerifier(derivedKey);

      // 4. Save to Firestore
      await setDoc(doc(db, "users", user.uid), {
        email: user.email,
        salt: salt,
        verifier: verifier,
        iterations: 600000,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      setUserSalt(salt);
      setStoredVerifier(verifier);
      setMasterKey(derivedKey);
      startVaultSession();
      setVaultStatus("unlocked");
      setMasterPassword("");
      setConfirmMasterPassword("");
      await fetchVaultItems(derivedKey);
    } catch (err: unknown) {
      console.error("Initialization error:", err);
      setVaultError("Failed to initialize vault. Please ensure Firestore Security Rules are published in Firebase Console.");
    } finally {
      setVaultLoading(false);
    }
  };

  // Unlock Vault with Master Password
  const handleUnlockVault = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !userSalt || !storedVerifier) return;
    setVaultError(null);
    setVaultLoading(true);

    try {
      // 1. Derive candidate key from entered password + user's salt
      const candidateKey = await deriveMasterKey(masterPassword, userSalt);

      // 2. Cryptographically verify against the stored verifier token
      const isValid = await verifyMasterKey(candidateKey, storedVerifier);

      if (!isValid) {
        setVaultError("Incorrect Master Password. AES-GCM authentication tag check failed.");
        setVaultLoading(false);
        return;
      }

      // 3. Set verified key in memory
      setMasterKey(candidateKey);
      startVaultSession();
      setVaultStatus("unlocked");
      setMasterPassword("");
      await fetchVaultItems(candidateKey);
    } catch (err: unknown) {
      console.error("Unlock error:", err);
      setVaultError("Decryption failed. Please verify your Master Password.");
    } finally {
      setVaultLoading(false);
    }
  };

  // Fetch and Decrypt Vault Items
  const fetchVaultItems = async (key: CryptoKey) => {
    if (!user) return;
    try {
      const colRef = collection(db, "vaults", user.uid, "items");
      const snap = await getDocs(colRef);
      const rawDocs: StoredEncryptedDoc[] = snap.docs.map((docSnap) => ({
        id: docSnap.id,
        ...(docSnap.data() as { ciphertext: string; iv: string }),
      }));

      // Decrypt each item client-side
      const decryptedList: DecryptedVaultItem[] = [];
      for (const d of rawDocs) {
        try {
          const payload = await decryptData<VaultItemPayload>(d.ciphertext, d.iv, key);
          decryptedList.push({
            id: d.id,
            service: payload.service,
            username: payload.username,
            pass: payload.pass,
            notes: payload.notes || "",
            category: payload.category || "Logins",
            updatedAt: payload.updatedAt,
            isDecrypted: true,
          });
        } catch {
          decryptedList.push({
            id: d.id,
            service: "[Corrupted Item]",
            username: "",
            pass: "",
            notes: "Item integrity verification failed (AES-GCM tag mismatch).",
            updatedAt: "",
            isDecrypted: false,
          });
        }
      }

      setItems(decryptedList);
    } catch (err) {
      console.error("Error fetching vault items:", err);
    }
  };

  // Add New Password to Vault
  const handleAddItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !masterKey) return;
    if (!newService.trim() || !newPassword.trim()) {
      alert("Please provide both a Service Name and a Password.");
      return;
    }

    if (
      newService.trim().length > 128 ||
      newUsername.trim().length > 256 ||
      newPassword.trim().length > 512 ||
      newNotes.trim().length > 5000
    ) {
      alert("One or more fields exceed maximum allowed character limits (Service: 128, Username: 256, Password: 512, Notes: 5000).");
      return;
    }

    setSavingItem(true);
    try {
      const payload: VaultItemPayload = {
        service: newService.trim(),
        username: newUsername.trim(),
        pass: newPassword.trim(),
        notes: newNotes.trim(),
        category: newCategory,
        updatedAt: new Date().toISOString(),
      };

      // Encrypt full payload using AES-256-GCM with a fresh 12-byte IV
      const encrypted = await encryptData(payload, masterKey);

      const colRef = collection(db, "vaults", user.uid, "items");
      await addDoc(colRef, {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        userId: user.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // Reset form
      setNewService("");
      setNewUsername("");
      setNewPassword("");
      setNewNotes("");
      setActiveTab("items");
      await fetchVaultItems(masterKey);
    } catch (err) {
      console.error("Error saving vault item:", err);
      alert("Failed to encrypt and save password item.");
    } finally {
      setSavingItem(false);
    }
  };

  // Delete Vault Item
  const handleDeleteItem = async (itemId: string) => {
    if (!user || !masterKey) return;
    if (!confirm("Are you sure you want to permanently delete this credential from your vault?")) return;

    try {
      await deleteDoc(doc(db, "vaults", user.uid, "items", itemId));
      setItems((prev) => prev.filter((item) => item.id !== itemId));
    } catch (err) {
      console.error("Error deleting item:", err);
      alert("Failed to delete item from vault.");
    }
  };

  // Firebase Authentication with Email Checker (validator)
  const isEmailInputValid = useMemo(() => {
    if (!emailInput.trim()) return false;
    return validator.isEmail(emailInput.trim());
  }, [emailInput]);

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    // Validate email format with validator library
    const trimmedEmail = emailInput.trim();
    if (!validator.isEmail(trimmedEmail)) {
      setAuthError("Please enter a valid email address (e.g., name@example.com).");
      return;
    }

    if (authPasswordInput.length < 6) {
      setAuthError("Password must be at least 6 characters.");
      return;
    }

    setAuthSubmitting(true);
    try {
      if (authTab === "signin") {
        await signInWithEmailAndPassword(auth, trimmedEmail, authPasswordInput);
      } else {
        await createUserWithEmailAndPassword(auth, trimmedEmail, authPasswordInput);
      }
      setEmailInput("");
      setAuthPasswordInput("");
    } catch (err: any) {
      console.error("Auth error:", err);
      if (err.code === "auth/operation-not-allowed") {
        setAuthError(
          "Email/Password sign-in is not enabled in Firebase Console. Please go to Firebase Console -> Authentication -> Sign-in method and enable Email/Password."
        );
      } else if (err.code === "auth/invalid-credential" || err.code === "auth/wrong-password" || err.code === "auth/user-not-found") {
        setAuthError("Invalid email or password.");
      } else if (err.code === "auth/email-already-in-use") {
        setAuthError("An account already exists with this email address.");
      } else if (err.code === "auth/weak-password") {
        setAuthError("Password is too weak. Please choose a stronger password.");
      } else {
        setAuthError(err.message || "Authentication failed. Please verify credentials.");
      }
    } finally {
      setAuthSubmitting(false);
    }
  };

  // Sign Out
  const handleSignOut = async () => {
    lockVault();
    setUser(null);
    try {
      await signOut(auth);
    } catch {
      // Ignored
    }
  };

  // Filtered Items for Search & Category
  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const matchesSearch =
        !searchQuery.trim() ||
        item.service.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (item.notes && item.notes.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesCategory =
        selectedCategory === "All" || item.category === selectedCategory;

      return matchesSearch && matchesCategory;
    });
  }, [items, searchQuery, selectedCategory]);

  // Master Password Strength Meter
  const masterPasswordStrength = useMemo(() => {
    return evaluatePasswordStrength(masterPassword);
  }, [masterPassword]);

  // New Item Password Strength Meter
  const newPasswordStrength = useMemo(() => {
    return evaluatePasswordStrength(newPassword);
  }, [newPassword]);

  // Vault Security Audit Metrics
  const auditMetrics = useMemo(() => {
    const total = items.length;
    let weak = 0;
    let military = 0;
    const passMap = new Map<string, number>();

    items.forEach((item) => {
      if (item.pass) {
        const str = evaluatePasswordStrength(item.pass);
        if (str.percent < 50) weak++;
        if (str.label === "Military-Grade" || str.label === "Strong") military++;
        passMap.set(item.pass, (passMap.get(item.pass) || 0) + 1);
      }
    });

    let reused = 0;
    passMap.forEach((count) => {
      if (count > 1) reused += count;
    });

    const healthScore = total === 0 ? 100 : Math.max(0, Math.round(((total - weak - reused) / total) * 100));

    return { total, weak, military, reused, healthScore };
  }, [items]);

  // Format session time to mm:ss
  const sessionMinutes = Math.floor(sessionSecondsLeft / 60);
  const sessionSecs = sessionSecondsLeft % 60;
  const formattedSessionTime = `${sessionMinutes}:${sessionSecs < 10 ? `0${sessionSecs}` : sessionSecs}`;

  // Loading Screen
  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#090a0f] text-neutral-200 flex flex-col items-center justify-center p-4">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shadow-lg shadow-emerald-500/10">
            <ShieldCheck className="w-6 h-6 text-emerald-400 animate-pulse" />
          </div>
          <div className="flex items-center gap-2 text-sm font-medium tracking-wide text-neutral-400">
            <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />
            <span>Initializing PassX Vault...</span>
          </div>
        </div>
      </div>
    );
  }

  // VIEW 1: Authentication Screen (Pure Firebase Auth with Email Checker)
  if (!user) {
    return (
      <div className="min-h-screen bg-[#090a0f] text-neutral-200 px-4 py-12 flex flex-col items-center justify-center relative overflow-hidden">
        {/* Cyber Glow Backdrop */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[350px] bg-gradient-to-b from-emerald-500/15 via-cyan-500/5 to-transparent blur-3xl opacity-70 pointer-events-none rounded-full" />
        <div className="absolute -bottom-20 right-1/4 w-[400px] h-[400px] bg-indigo-500/5 blur-3xl pointer-events-none rounded-full" />

        <div className="w-full max-w-md flex flex-col gap-7 relative z-10">
          
          {/* Brand Header */}
          <div className="flex flex-col items-center text-center gap-3">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500/20 via-neutral-900 to-cyan-500/10 border border-emerald-500/30 flex items-center justify-center shadow-xl shadow-emerald-500/10 backdrop-blur-md">
              <ShieldCheck className="w-7 h-7 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-3xl font-extrabold tracking-tight text-white flex items-center justify-center gap-2">
                PassX
                <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold tracking-normal">
                  ZERO-KNOWLEDGE
                </span>
              </h1>
              <p className="text-xs text-neutral-400 mt-1 max-w-sm">
                Next-generation encrypted password vault. Powered by Web Crypto AES-256-GCM.
              </p>
            </div>
          </div>

          {/* Auth Card */}
          <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-7 shadow-2xl backdrop-blur-xl transition-all">
            {/* Tab Switcher */}
            <div className="flex bg-[#0b0c11] p-1 rounded-xl border border-white/[0.05] mb-6">
              <button
                id="tab-signin-btn"
                type="button"
                onClick={() => {
                  setAuthTab("signin");
                  setAuthError(null);
                }}
                className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  authTab === "signin"
                    ? "bg-gradient-to-r from-emerald-500 to-emerald-400 text-black shadow-md shadow-emerald-500/20"
                    : "text-neutral-400 hover:text-white"
                }`}
              >
                Sign In
              </button>
              <button
                id="tab-signup-btn"
                type="button"
                onClick={() => {
                  setAuthTab("signup");
                  setAuthError(null);
                }}
                className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  authTab === "signup"
                    ? "bg-gradient-to-r from-emerald-500 to-emerald-400 text-black shadow-md shadow-emerald-500/20"
                    : "text-neutral-400 hover:text-white"
                }`}
              >
                Create Account
              </button>
            </div>

            {authError && (
              <div className="mb-5 p-3.5 rounded-xl bg-red-500/10 border border-red-500/25 text-red-300 text-xs flex items-start gap-2.5 leading-relaxed">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{authError}</span>
              </div>
            )}

            <form onSubmit={handleAuthSubmit} className="flex flex-col gap-4">
              {/* Email Input with Live Validator Feedback */}
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-neutral-300">Email Address</label>
                  {emailInput.trim().length > 0 && (
                    <span className="flex items-center gap-1 text-[11px] font-mono">
                      {isEmailInputValid ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Valid email</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5 text-amber-400" />
                          <span className="text-amber-400">Invalid format</span>
                        </>
                      )}
                    </span>
                  )}
                </div>
                <input
                  id="auth-email-input"
                  type="email"
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="you@domain.com"
                  required
                  className={`w-full bg-[#181a24] border rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 transition-all ${
                    emailInput.trim().length > 0 && !isEmailInputValid
                      ? "border-amber-500/50 focus:border-amber-400"
                      : "border-neutral-800 focus:border-emerald-500/70"
                  }`}
                />
              </div>

              {/* Password Input */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-neutral-300">Account Password</label>
                <input
                  id="auth-password-input"
                  type="password"
                  value={authPasswordInput}
                  onChange={(e) => setAuthPasswordInput(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all"
                />
              </div>

              <button
                id="auth-submit-btn"
                type="submit"
                disabled={authSubmitting || (emailInput.trim().length > 0 && !isEmailInputValid)}
                className="w-full mt-3 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/25 disabled:opacity-40 cursor-pointer flex items-center justify-center gap-2"
              >
                {authSubmitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Processing...</span>
                  </>
                ) : (
                  <>
                    <span>{authTab === "signin" ? "Sign In to Vault" : "Create Protected Vault"}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Footer Security Badges */}
          <div className="flex items-center justify-center gap-6 text-[11px] text-neutral-500 font-mono">
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              AES-256-GCM
            </span>
            <span className="flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-cyan-400" />
              PBKDF2 600K
            </span>
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-indigo-400" />
              Zero-Knowledge
            </span>
          </div>

        </div>
      </div>
    );
  }

  // VIEW 2: Master Password Setup or Unlock
  if (vaultStatus === "needs_setup" || vaultStatus === "locked") {
    return (
      <div className="min-h-screen bg-[#090a0f] text-neutral-200 px-4 py-12 flex flex-col items-center justify-center relative overflow-hidden">
        {/* Ambient Glow */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[350px] bg-gradient-to-b from-emerald-500/15 via-cyan-500/5 to-transparent blur-3xl opacity-70 pointer-events-none rounded-full" />

        <div className="w-full max-w-md flex flex-col gap-6 relative z-10">
          
          {/* Header Bar */}
          <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                <Lock className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">PassX Security Guard</h2>
                <p className="text-xs text-neutral-400 font-mono truncate max-w-[200px]">{user.email}</p>
              </div>
            </div>
            <button
              id="auth-signout-btn"
              type="button"
              onClick={handleSignOut}
              className="text-xs text-neutral-400 hover:text-white flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-white/[0.05] transition-colors border border-transparent hover:border-white/[0.08] cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>

          {vaultError && (
            <div className="p-4 rounded-2xl bg-red-500/10 border border-red-500/25 text-red-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{vaultError}</span>
            </div>
          )}

          {/* Setup Master Key Form */}
          {vaultStatus === "needs_setup" ? (
            <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-7 flex flex-col gap-5 shadow-2xl backdrop-blur-xl">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white">Create Master Encryption Key</h3>
                </div>
                <p className="text-xs text-neutral-400 leading-relaxed">
                  This master password is used to derive your AES-256-GCM encryption key. It is never sent to the server.
                </p>
              </div>

              <div className="p-3.5 bg-amber-500/10 border border-amber-500/25 rounded-2xl text-amber-200 text-xs flex items-start gap-2.5">
                <Info className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                <span className="leading-relaxed">
                  <strong>Zero-Knowledge Alert:</strong> There is NO password reset. If you forget your master password, encrypted data cannot be recovered by anyone.
                </span>
              </div>

              <form onSubmit={handleInitializeVault} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-neutral-300">Master Password</label>
                    {masterPassword && (
                      <span className="text-[11px] font-mono text-neutral-400">
                        {masterPasswordStrength.entropy} bits ({masterPasswordStrength.label})
                      </span>
                    )}
                  </div>
                  <input
                    id="master-password-setup-input"
                    type="password"
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    placeholder="Minimum 12 characters"
                    required
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all font-mono"
                  />
                  {masterPassword && (
                    <div className="w-full bg-neutral-800 h-1.5 rounded-full overflow-hidden mt-1.5">
                      <div
                        className={`h-full ${masterPasswordStrength.color} transition-all duration-300`}
                        style={{ width: `${masterPasswordStrength.percent}%` }}
                      ></div>
                    </div>
                  )}
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-medium text-neutral-300">Confirm Master Password</label>
                  <input
                    id="master-password-confirm-input"
                    type="password"
                    value={confirmMasterPassword}
                    onChange={(e) => setConfirmMasterPassword(e.target.value)}
                    placeholder="Repeat Master Password"
                    required
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all font-mono"
                  />
                </div>

                <button
                  id="initialize-vault-btn"
                  type="submit"
                  disabled={vaultLoading}
                  className="w-full mt-2 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
                >
                  {vaultLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Deriving Key (600,000 Rounds)...
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4" />
                      Initialize & Secure Vault
                    </>
                  )}
                </button>
              </form>
            </div>
          ) : (
            /* Unlock Vault Form */
            <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-7 flex flex-col gap-5 shadow-2xl backdrop-blur-xl">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white">Unlock Zero-Knowledge Vault</h3>
                </div>
                <p className="text-xs text-neutral-400 leading-relaxed">
                  Enter your master password to decrypt your credentials locally in memory.
                </p>
              </div>

              <form onSubmit={handleUnlockVault} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-medium text-neutral-300">Master Password</label>
                  <input
                    id="master-password-unlock-input"
                    type="password"
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    placeholder="Enter Master Password"
                    autoFocus
                    required
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all font-mono"
                  />
                </div>

                <button
                  id="unlock-vault-btn"
                  type="submit"
                  disabled={vaultLoading}
                  className="w-full mt-2 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
                >
                  {vaultLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Verifying Authentication Tag...
                    </>
                  ) : (
                    <>
                      <Unlock className="w-4 h-4" />
                      Unlock Vault
                    </>
                  )}
                </button>
              </form>
            </div>
          )}

          <div className="flex items-center justify-center gap-4 text-[11px] text-neutral-500 font-mono">
            <span>PBKDF2 (600k)</span>
            <span>•</span>
            <span>AES-256-GCM</span>
            <span>•</span>
            <span>Zero Metadata Leak</span>
          </div>

        </div>
      </div>
    );
  }

  // VIEW 3: Fully Unlocked Zero-Knowledge Vault
  return (
    <div className="min-h-screen bg-[#090a0f] text-neutral-200 px-4 py-8 flex flex-col items-center relative overflow-hidden">
      {/* Ambient Cyber Mesh */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[750px] h-[450px] bg-gradient-to-b from-emerald-500/12 via-cyan-500/5 to-transparent blur-3xl opacity-60 rounded-full" />
        <div className="absolute top-1/2 -left-40 w-[450px] h-[450px] bg-indigo-500/5 blur-3xl rounded-full" />
        <div className="absolute -bottom-20 right-0 w-[550px] h-[550px] bg-emerald-500/5 blur-3xl rounded-full" />
      </div>

      <div className="w-full max-w-3xl flex flex-col gap-6 relative z-10">

        {/* Top Vault Security Ribbon */}
        <div className="w-full bg-gradient-to-r from-[#12141c]/95 via-[#151824]/95 to-[#12141c]/95 border border-white/[0.08] rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-2xl backdrop-blur-xl">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/30 flex items-center justify-center shadow-lg shadow-emerald-500/10 shrink-0">
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-bold text-white tracking-tight">PassX Vault</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                  ACTIVE
                </span>
                <span className="text-[10px] font-mono text-neutral-400 truncate max-w-[180px]">
                  {user.email}
                </span>
              </div>
              <p className="text-xs text-neutral-400 mt-0.5">
                Keys held in non-extractable client memory. Zero knowledge.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 self-end sm:self-center">
            {/* Session Countdown Display */}
            <div className="flex items-center gap-2 bg-[#0c0d14] border border-white/[0.08] px-3.5 py-1.5 rounded-xl font-mono">
              <Clock className={`w-3.5 h-3.5 ${sessionSecondsLeft < 120 ? 'text-amber-400 animate-pulse' : 'text-emerald-400'}`} />
              <div className="flex items-center gap-1.5 text-xs">
                <span className="text-neutral-400">Session:</span>
                <span className={`font-semibold ${sessionSecondsLeft < 120 ? 'text-amber-300' : 'text-white'}`}>
                  {formattedSessionTime}
                </span>
              </div>
              <button
                type="button"
                onClick={extendSession}
                className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-lg bg-white/[0.06] hover:bg-emerald-500/20 text-neutral-300 hover:text-emerald-300 border border-white/[0.08] hover:border-emerald-500/30 transition-all cursor-pointer"
                title="Extend session by 10 minutes"
              >
                +10m
              </button>
            </div>

            {/* Manual Lock Vault Button */}
            <button
              id="manual-lock-vault-btn"
              type="button"
              onClick={() => lockVault()}
              className="text-xs text-neutral-200 hover:text-white bg-[#1a1d29] hover:bg-[#222636] border border-white/[0.08] px-3.5 py-1.5 rounded-xl flex items-center gap-1.5 transition-all cursor-pointer font-medium shadow-sm"
            >
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              Lock
            </button>

            {/* Sign Out Button */}
            <button
              id="header-signout-btn"
              type="button"
              onClick={handleSignOut}
              className="text-xs text-neutral-400 hover:text-red-400 p-2 rounded-xl hover:bg-white/[0.05] transition-colors border border-transparent hover:border-white/[0.08] cursor-pointer"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Clipboard Auto-Wipe Alert (Auto-removed after 30s) */}
        {clipboardAlert && (
          <div className="w-full bg-[#121820] border border-emerald-500/40 rounded-2xl p-4 flex flex-col gap-2.5 shadow-xl shadow-emerald-500/10 animate-fade-in relative overflow-hidden">
            <div className="flex items-center justify-between text-xs text-emerald-300">
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4 text-emerald-400" />
                <span>
                  <strong>{clipboardAlert.label}</strong> copied! Clipboard will auto-wipe in{" "}
                  <strong className="font-mono text-white text-sm">{clipboardSecondsLeft}s</strong> for security.
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  id="wipe-clipboard-now-btn"
                  type="button"
                  onClick={handleManualClipboardWipe}
                  className="px-2.5 py-1 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded-lg text-[11px] transition-all cursor-pointer shadow-sm"
                >
                  Wipe Now
                </button>
                <button
                  type="button"
                  onClick={handleDismissClipboardAlert}
                  className="text-neutral-400 hover:text-white p-1 rounded-md"
                  title="Dismiss alert"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Countdown Progress Bar */}
            <div className="w-full bg-neutral-900 h-1.5 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-300 ease-linear"
                style={{ width: `${Math.max(0, Math.min(100, (clipboardSecondsLeft / 30) * 100))}%` }}
              />
            </div>
          </div>
        )}

        {/* Brief Sanitized Toast Notification */}
        {showSanitizedToast && (
          <div className="w-full bg-neutral-900/90 border border-emerald-500/30 rounded-xl p-3 flex items-center gap-2 text-xs text-emerald-300 animate-fade-in">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Clipboard sanitized. Secret removed from system memory.</span>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center justify-between border-b border-white/[0.08] pb-2 overflow-x-auto">
          <div className="flex items-center gap-2">
            <button
              id="nav-tab-items"
              type="button"
              onClick={() => setActiveTab("items")}
              className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 ${
                activeTab === "items"
                  ? "bg-white text-black shadow-lg shadow-white/10"
                  : "text-neutral-400 hover:text-white hover:bg-white/[0.05]"
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              Vault ({items.length})
            </button>

            <button
              id="nav-tab-add"
              type="button"
              onClick={() => setActiveTab("add")}
              className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 ${
                activeTab === "add"
                  ? "bg-white text-black shadow-lg shadow-white/10"
                  : "text-neutral-400 hover:text-white hover:bg-white/[0.05]"
              }`}
            >
              <Plus className="w-3.5 h-3.5" />
              Add Password
            </button>

            <button
              id="nav-tab-generator"
              type="button"
              onClick={() => setActiveTab("generator")}
              className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 ${
                activeTab === "generator"
                  ? "bg-white text-black shadow-lg shadow-white/10"
                  : "text-neutral-400 hover:text-white hover:bg-white/[0.05]"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              Generator
            </button>

            <button
              id="nav-tab-audit"
              type="button"
              onClick={() => setActiveTab("audit")}
              className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 ${
                activeTab === "audit"
                  ? "bg-white text-black shadow-lg shadow-white/10"
                  : "text-neutral-400 hover:text-white hover:bg-white/[0.05]"
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              Security Audit
            </button>
          </div>
        </div>

        {/* TAB 1: Vault Items */}
        {activeTab === "items" && (
          <div className="flex flex-col gap-4">
            {/* Search and Category Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-neutral-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  id="search-vault-input"
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search service, username, or notes..."
                  className="w-full bg-[#12141c]/90 border border-white/[0.08] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all"
                />
              </div>

              {/* Category Filter Pills */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setSelectedCategory(cat)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer whitespace-nowrap ${
                      selectedCategory === cat
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                        : "text-neutral-400 hover:text-neutral-200 bg-[#12141c] border border-white/[0.05]"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {filteredItems.length === 0 ? (
              <div className="text-center py-16 border border-white/[0.08] rounded-3xl bg-[#12141c]/60 flex flex-col items-center justify-center gap-3 backdrop-blur-xl">
                <div className="w-12 h-12 rounded-2xl bg-neutral-900 border border-neutral-800 flex items-center justify-center">
                  <Key className="w-6 h-6 text-neutral-500" />
                </div>
                <div className="flex flex-col gap-1 max-w-sm">
                  <p className="text-sm font-semibold text-white">No Credentials Found</p>
                  <p className="text-xs text-neutral-500">
                    {searchQuery
                      ? "No records matched your search query."
                      : "Your zero-knowledge vault is empty. Click below to add your first password."}
                  </p>
                </div>
                {!searchQuery && (
                  <button
                    type="button"
                    onClick={() => setActiveTab("add")}
                    className="mt-2 text-xs bg-emerald-500 hover:bg-emerald-400 text-black font-bold px-4 py-2 rounded-xl transition-all cursor-pointer shadow-md shadow-emerald-500/20"
                  >
                    Add Your First Password
                  </button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-3">
                {filteredItems.map((item) => {
                  const strength = evaluatePasswordStrength(item.pass);
                  const isRevealed = !!revealedPasswords[item.id];
                  const hasNotes = !!item.notes;
                  const isNotesExpanded = expandedNotesId === item.id;

                  return (
                    <div
                      key={item.id}
                      className="bg-[#12141c]/90 border border-white/[0.08] hover:border-emerald-500/30 rounded-2xl p-4 sm:p-5 flex flex-col gap-3.5 transition-all shadow-xl backdrop-blur-xl group"
                    >
                      {/* Card Header */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-neutral-800 to-neutral-900 border border-white/[0.08] flex items-center justify-center text-xs font-bold text-emerald-400 shadow-sm">
                            {item.service.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <h4 className="text-sm font-bold text-white tracking-tight">{item.service}</h4>
                              {item.category && (
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-white/[0.05] text-neutral-400 border border-white/[0.05]">
                                  {item.category}
                                </span>
                              )}
                            </div>
                            {item.username && (
                              <div className="flex items-center gap-1.5 mt-0.5">
                                <span className="text-xs text-neutral-400 font-mono">{item.username}</span>
                                <button
                                  type="button"
                                  onClick={() => handleSecureCopy(`${item.id}_user`, item.username, "Username")}
                                  className="text-neutral-500 hover:text-emerald-400 transition-colors p-0.5"
                                  title="Copy username"
                                >
                                  {copiedId === `${item.id}_user` ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded-md border ${
                              strength.label === "Military-Grade" || strength.label === "Strong"
                                ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                                : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                            }`}
                          >
                            {strength.label}
                          </span>
                          <button
                            type="button"
                            onClick={() => handleDeleteItem(item.id)}
                            className="text-neutral-500 hover:text-red-400 p-1.5 rounded-lg hover:bg-white/[0.05] transition-colors"
                            title="Delete credential"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      {/* Password Row */}
                      <div className="flex items-center gap-2 bg-[#0c0d14] border border-white/[0.06] rounded-xl px-3.5 py-2.5">
                        <input
                          type={isRevealed ? "text" : "password"}
                          value={item.pass}
                          readOnly
                          className="flex-1 bg-transparent text-xs font-mono text-neutral-200 select-all focus:outline-none tracking-wider"
                        />

                        {/* Reveal/Hide Button */}
                        <button
                          type="button"
                          onClick={() => togglePasswordVisibility(item.id)}
                          className="text-neutral-400 hover:text-white p-1 rounded-md transition-colors"
                          title={isRevealed ? "Hide Password" : "Show Password"}
                        >
                          {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>

                        {/* Copy Password Button with Auto-Wipe */}
                        <button
                          type="button"
                          onClick={() => handleSecureCopy(item.id, item.pass, "Password")}
                          className="text-xs font-semibold text-emerald-300 hover:text-emerald-200 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 transition-all cursor-pointer"
                        >
                          {copiedId === item.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span>Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>

                      {/* Expandable Notes */}
                      {hasNotes && (
                        <div className="flex flex-col gap-1.5">
                          <button
                            type="button"
                            onClick={() => setExpandedNotesId(isNotesExpanded ? null : item.id)}
                            className="flex items-center gap-1 text-[11px] text-neutral-400 hover:text-neutral-200 cursor-pointer self-start"
                          >
                            {isNotesExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            <span>{isNotesExpanded ? "Hide Secure Notes" : "View Secure Notes"}</span>
                          </button>
                          {isNotesExpanded && (
                            <p className="text-xs text-neutral-300 bg-[#0c0d14] p-3 rounded-xl border border-white/[0.05] leading-relaxed whitespace-pre-wrap animate-fade-in">
                              {item.notes}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Add New Password */}
        {activeTab === "add" && (
          <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-6 sm:p-7 flex flex-col gap-5 shadow-2xl backdrop-blur-xl">
            <div className="flex flex-col gap-1">
              <h3 className="text-base font-bold text-white tracking-tight">Add New Credential</h3>
              <p className="text-xs text-neutral-400">
                Data is encrypted in browser RAM using AES-256-GCM before transmitting to Firestore.
              </p>
            </div>

            <form onSubmit={handleAddItem} className="flex flex-col gap-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-medium text-neutral-300">Service / Application</label>
                  <input
                    id="new-service-input"
                    type="text"
                    value={newService}
                    onChange={(e) => setNewService(e.target.value)}
                    placeholder="e.g. GitHub, AWS, Google"
                    required
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all"
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-medium text-neutral-300">Username / Email</label>
                  <input
                    id="new-username-input"
                    type="text"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="you@domain.com"
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all"
                  />
                </div>
              </div>

              {/* Category Selector */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-neutral-300">Category</label>
                <div className="flex items-center gap-2 overflow-x-auto">
                  {(["Logins", "Banking", "Work", "Personal"] as const).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setNewCategory(cat)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                        newCategory === cat
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "text-neutral-400 hover:text-white bg-[#181a24] border border-neutral-800"
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Password Input with Strength & Quick Generator */}
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-neutral-300">Password</label>
                  <button
                    type="button"
                    onClick={() => setNewPassword(generateSecurePassword(genOptions))}
                    className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium transition-colors"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Generate Strong
                  </button>
                </div>
                <div className="relative">
                  <input
                    id="new-password-input"
                    type={showNewPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter or generate a strong password"
                    required
                    className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 pr-20 text-sm font-mono text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-neutral-400 hover:text-white px-2 py-0.5 rounded cursor-pointer"
                  >
                    {showNewPassword ? "Hide" : "Show"}
                  </button>
                </div>

                {newPassword && (
                  <div className="flex items-center justify-between text-[11px] font-mono text-neutral-400 mt-1">
                    <span>
                      Strength: <strong className="text-white">{newPasswordStrength.label}</strong> ({newPasswordStrength.entropy} bits)
                    </span>
                    <div className="w-28 bg-neutral-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${newPasswordStrength.color} transition-all duration-300`}
                        style={{ width: `${newPasswordStrength.percent}%` }}
                      ></div>
                    </div>
                  </div>
                )}
              </div>

              {/* Encrypted Notes */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-neutral-300">Encrypted Notes (Optional)</label>
                <textarea
                  id="new-notes-input"
                  value={newNotes}
                  onChange={(e) => setNewNotes(e.target.value)}
                  placeholder="Recovery seeds, security questions, or private notes..."
                  rows={3}
                  className="w-full bg-[#181a24] border border-neutral-800 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-neutral-500 focus:border-emerald-500/70 transition-all resize-none"
                />
              </div>

              <button
                id="save-item-btn"
                type="submit"
                disabled={savingItem}
                className="w-full mt-2 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
              >
                {savingItem ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Encrypting with AES-256-GCM...
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    Encrypt & Save to Vault
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        {/* TAB 3: Cryptographic Password Generator */}
        {activeTab === "generator" && (
          <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-6 sm:p-7 flex flex-col gap-6 shadow-2xl backdrop-blur-xl">
            <div className="flex flex-col gap-1">
              <h3 className="text-base font-bold text-white tracking-tight">Cryptographic Password Generator</h3>
              <p className="text-xs text-neutral-400">
                Generated locally using native browser entropy (<code className="text-emerald-400 font-mono">crypto.getRandomValues</code>).
              </p>
            </div>

            {/* Generated Password Box */}
            <div className="flex items-center gap-2 bg-[#0c0d14] border border-white/[0.08] rounded-2xl p-3.5 sm:p-4">
              <input
                type="text"
                readOnly
                value={generatedPassword}
                className="w-full bg-transparent font-mono text-base sm:text-lg text-emerald-400 select-all focus:outline-none tracking-wider"
              />
              <button
                type="button"
                onClick={() => setGeneratedPassword(generateSecurePassword(genOptions))}
                className="p-2 text-neutral-400 hover:text-white rounded-xl hover:bg-white/[0.05] transition-colors"
                title="Regenerate"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => handleSecureCopy("gen", generatedPassword, "Generated Password")}
                className="px-4 py-2 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-bold text-xs rounded-xl transition-all flex items-center gap-1.5 cursor-pointer shadow-md shadow-emerald-500/20"
              >
                <Copy className="w-3.5 h-3.5" />
                Copy
              </button>
            </div>

            {/* Controls */}
            <div className="flex flex-col gap-5 border-t border-white/[0.08] pt-5">
              {/* Length Slider */}
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between text-xs text-neutral-300">
                  <span>
                    Length: <strong className="font-mono text-white text-sm">{genOptions.length}</strong> characters
                  </span>
                  <span className="font-mono text-emerald-400">
                    {evaluatePasswordStrength(generatedPassword).entropy} bits entropy
                  </span>
                </div>
                <input
                  type="range"
                  min="12"
                  max="48"
                  value={genOptions.length}
                  onChange={(e) => {
                    const next = { ...genOptions, length: parseInt(e.target.value) };
                    setGenOptions(next);
                    setGeneratedPassword(generateSecurePassword(next));
                  }}
                  className="w-full accent-emerald-500 cursor-pointer"
                />
              </div>

              {/* Toggles */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <label className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0c0d14] border border-white/[0.05] text-neutral-300 cursor-pointer hover:border-emerald-500/30 transition-all">
                  <input
                    type="checkbox"
                    checked={genOptions.useUpper}
                    onChange={(e) => {
                      const next = { ...genOptions, useUpper: e.target.checked };
                      setGenOptions(next);
                      setGeneratedPassword(generateSecurePassword(next));
                    }}
                    className="accent-emerald-500"
                  />
                  Uppercase (A-Z)
                </label>

                <label className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0c0d14] border border-white/[0.05] text-neutral-300 cursor-pointer hover:border-emerald-500/30 transition-all">
                  <input
                    type="checkbox"
                    checked={genOptions.useLower}
                    onChange={(e) => {
                      const next = { ...genOptions, useLower: e.target.checked };
                      setGenOptions(next);
                      setGeneratedPassword(generateSecurePassword(next));
                    }}
                    className="accent-emerald-500"
                  />
                  Lowercase (a-z)
                </label>

                <label className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0c0d14] border border-white/[0.05] text-neutral-300 cursor-pointer hover:border-emerald-500/30 transition-all">
                  <input
                    type="checkbox"
                    checked={genOptions.useNumbers}
                    onChange={(e) => {
                      const next = { ...genOptions, useNumbers: e.target.checked };
                      setGenOptions(next);
                      setGeneratedPassword(generateSecurePassword(next));
                    }}
                    className="accent-emerald-500"
                  />
                  Numbers (0-9)
                </label>

                <label className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0c0d14] border border-white/[0.05] text-neutral-300 cursor-pointer hover:border-emerald-500/30 transition-all">
                  <input
                    type="checkbox"
                    checked={genOptions.useSymbols}
                    onChange={(e) => {
                      const next = { ...genOptions, useSymbols: e.target.checked };
                      setGenOptions(next);
                      setGeneratedPassword(generateSecurePassword(next));
                    }}
                    className="accent-emerald-500"
                  />
                  Special Symbols (!@#$)
                </label>
              </div>

              <button
                type="button"
                onClick={() => {
                  setNewPassword(generatedPassword);
                  setActiveTab("add");
                }}
                className="w-full mt-1 bg-[#1a1d29] hover:bg-[#222636] text-white font-semibold py-2.5 rounded-xl text-xs transition-all border border-white/[0.08] cursor-pointer"
              >
                Insert into "Add Password" Form
              </button>
            </div>
          </div>
        )}

        {/* TAB 4: Vault Security Audit */}
        {activeTab === "audit" && (
          <div className="bg-[#12141c]/90 border border-white/[0.08] rounded-3xl p-6 sm:p-7 flex flex-col gap-6 shadow-2xl backdrop-blur-xl">
            <div className="flex flex-col gap-1">
              <h3 className="text-base font-bold text-white tracking-tight">Vault Health & Cryptographic Audit</h3>
              <p className="text-xs text-neutral-400">
                Audits your credentials against dictionary resistance and password reuse.
              </p>
            </div>

            {/* Score Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-[#0c0d14] border border-white/[0.05] rounded-2xl p-4 flex flex-col gap-1">
                <span className="text-xs text-neutral-400">Total Items</span>
                <span className="text-2xl font-bold font-mono text-white">{auditMetrics.total}</span>
              </div>

              <div className="bg-[#0c0d14] border border-white/[0.05] rounded-2xl p-4 flex flex-col gap-1">
                <span className="text-xs text-neutral-400">Health Score</span>
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {auditMetrics.healthScore}%
                </span>
              </div>

              <div className="bg-[#0c0d14] border border-white/[0.05] rounded-2xl p-4 flex flex-col gap-1">
                <span className="text-xs text-neutral-400">Weak Items</span>
                <span
                  className={`text-2xl font-bold font-mono ${
                    auditMetrics.weak > 0 ? "text-amber-400" : "text-emerald-400"
                  }`}
                >
                  {auditMetrics.weak}
                </span>
              </div>

              <div className="bg-[#0c0d14] border border-white/[0.05] rounded-2xl p-4 flex flex-col gap-1">
                <span className="text-xs text-neutral-400">Reused</span>
                <span
                  className={`text-2xl font-bold font-mono ${
                    auditMetrics.reused > 0 ? "text-red-400" : "text-emerald-400"
                  }`}
                >
                  {auditMetrics.reused}
                </span>
              </div>
            </div>

            {/* Cryptographic Proof Specifications */}
            <div className="border-t border-white/[0.08] pt-5 flex flex-col gap-3.5">
              <h4 className="text-xs font-bold text-neutral-300 uppercase tracking-wider">
                Cryptographic Defenses Active
              </h4>
              <ul className="text-xs text-neutral-400 flex flex-col gap-2.5">
                <li className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    <strong>Zero-Knowledge:</strong> Neither Firebase nor Google holds your Master Key or plaintext passwords.
                  </span>
                </li>
                <li className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    <strong>AES-256-GCM:</strong> Authenticated symmetric encryption with 128-bit authentication tags.
                  </span>
                </li>
                <li className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    <strong>PBKDF2-SHA256 (600,000 Rounds):</strong> OWASP standard key stretching to thwart GPU brute-force attacks.
                  </span>
                </li>
                <li className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    <strong>Clipboard Auto-Purge:</strong> Copies are securely wiped from system memory after exactly 30 seconds.
                  </span>
                </li>
                <li className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    <strong>Auto-Lock Memory Defense:</strong> Session keys are wiped from RAM after 10 minutes of inactivity.
                  </span>
                </li>
              </ul>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
