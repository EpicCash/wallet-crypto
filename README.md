# wallet-crypto
epic-wallet cryptography manager written in Python (BETA)

# [Packages]

`pip install cryptography`
`pip install mnemonic`

# [How to use]

```
# Create new wallet:
your_password = 'YOUR PASSWORD'
wallet = WalletSeed().create(password=your_password)

print(wallet.mnemonics)
```

```
# Import wallet from mnemonics:
your_mnemonics = "YOUR MNEMONIC SEED PHRASE"
wallet = WalletSeed().from_mnemonics(your_mnemonics)

print(wallet.seed_as_str())
```

```
# Import wallet from existing wallet.seed file:
with open('wallet.seed', 'r') as file:
  encrypted_seed_dict = json.dump(file)
your_password = 'YOUR PASSWORD'

wallet = WalletSeed().from_encrypted_seed(encrypted_seed_dict, your_password)

print(wallet.mnemonics)
```
