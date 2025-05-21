# 🔐 CryptVault — Because One Lock Was Just Too Boring
Say hello to CryptVault, the password manager that doesn’t just secure your secrets — it throws them in a digital vault, double padlocks it, sets booby traps, and adds a nice lil' icon on top just to look cute 😌

Yeah, it’s built in Python. But don’t let that fool you. This isn’t some half-baked side project — this is a production-level, smooth-gliding, encryption-crazy, UI-polished beast that takes itself very seriously (but we don’t).

Encrypted, overengineered, polished AF, and yes — it has an icon now 😌✨

# 🚀🧨 Features (a.k.a. “Did you really need all this?” – Yes. Yes I did.)
- 🎨 Polished UI: Light theme 🌞, calm colors 🎨, and smoother than your Wi-Fi during power cut ⚡

- 🔐 Multi-Factor Encryption (MFE): Encrypts your stuff not once, but TWICE. Two keys 🔑🔑, two vaults 🔒🔒. Trust issues? We gotchu 😤

- 🧠 Keyring Storage: No plaintext allowed 🚫. Keys live in OS-level vaults like royalty 👑

- 📬 Email Verification: Because we don’t trust anyone, not even you 🕵️‍♂️✉️

- 🗂️ Dynamic File Storage: Uses tempdir and appdata folders like a responsible adult 🧳🧼

- 📃 Rotating Logs: Keeps logs rotating 🌀, errors logged 🧾, and backs up tea ☕

- 🚫 Zero Drama: No memory leaks 💧, no lag 🚀, no crash 💥 = pure zen mode 🧘‍♂️

- 🛠️ Modular Setup: Clean structure that even Marie Kondo would approve 🗃️✨

- 🖼️ App Icon: Yup. It has a face now. And it’s cute 😎🖼️

# 🛠️📦 Installation (Your entry to the VIP lounge)
```
git clone <This repo>
cd PractisePlayground
pip install -r requirements.txt
```

# ▶️ How to Launch This App
```
python main.py
```
- 🔰 First time? You’ll get a welcome parade 🥳 with email verification and encryption madness 🎪

- 🔁 Next runs? Smooth login 🪄, vault unlock 🔓, good vibes only 🌈

# 🧪🤓 Developer Notes
-  ⚡ Fernet x2 = Ultra Secure – This thing encrypts better than your brain forgets math formulas

- 🗝️ Keys go to system vaults — not .txt files like peasants 😤

- 📫 Email verification on setup, because “hello hacker” is not our onboarding strategy 💅

- 📊 Rotating log files — logs, backups, and even your tears when it breaks (it won’t) 😢

- 🧼 Handles exceptions like a boss — no crashes, no mess

- 🌐 Uses appdata & tempdir per user. Plug, play, peace. 🔌

- 🧠 UI = Clean, responsive, and will make you wonder if this is really Tkinter 😳

# 🧱 Project Structure (aka: Yes, we planned this)
```
CryptVault/
├── main.py                   # 💥 Main launcher
├── .env                      # 🕵️‍♂️ Secret lair
├── requirements.txt          # 🧙 Python spellbook
├── README.md                 # 📖 You're here
│
├── app/
│   ├── app.py                # 🔑 Password vault UI
│   ├── searchwindow.py       # 🔑 Password vault UI
│   ├── edit_dialog.py        # 🔑 Password vault UI
│   ├── .env                  # 🧩 App-specific configs
│
└── auth/
    ├── SecureLayer.py        # 🧠 Double encryption wizardry
    ├── login.py              # 🧾 Login screen
    ├── onboarding.py         # ✉️ Email-verified setup
    └── auth_logging.py       # 📃 Logging magic

```

# 🎨 UI & UX Goals
- ☀️ Light theme = No more burning your retina at 2AM

- 🧊 Super responsive, like it’s reading your mind 🧠

- 🧼 Clean and minimalist — because ugly apps are a crime 🚔

👑 Credits
Crafted with maximum laziness 💻🧽 by Sai Vignesh aka 𝓜я. ᴠᴇɴɢᴇᴀɴᴄᴇ (Instagram: [itz_mr.voidwalker])
Because if you're gonna build a password manager...
why not make it fabulous AND paranoid? 💅🔐💥

📜 License
Free. Open-source. Plagiarize responsibly.
Just don’t break the vibe 😎🧃

⚠️ Disclaimer:
Everything described above is 100% just for fun, because who doesn’t love sounding like they built Fort Knox when really it’s just a Python app with some caffeine ☕ and code sweat?
So chill, enjoy the sarcasm, and don’t take me too seriously — unless you want to, then I’m flattered. 😎
