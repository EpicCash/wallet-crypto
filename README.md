# wallet-seed-py
    Epic-Cash Wallet cryptography wrapped in Python:

    create() -> Create completely new epic-wallet insatnce
    from_bytes() -> Initialize epic-wallet from seed (bytes)
    from_mnemonic() -> Initialize epic-wallet from mnemonic seed-phrase (str)
    from_encrypted_seed() -> Initialize epic-wallet from previously encrypted seed (dict)
    save_to_file() -> Save encrypted wallet seed data in file (JSON)
    seed_as_str() -> Return wallet seed as string

## Packages
`pip install cryptography`

`pip install mnemonic`
## How to use
```
from seed import WalletSeed

your_password = "YOUR PASSWORD"
your_mnemonics = "YOUR MNEMONIC SEED PHRASE"
your_path_to_seed = "PATH TO WALLET.SEED"


# Create new wallet:
wallet = WalletSeed(password=your_password)
print(wallet.info)


# Import wallet from mnemonic:
wallet = WalletSeed(mnemonics=your_mnemonics)
print(wallet.info)


# Import wallet from existing 'wallet.seed' file:
wallet = WalletSeed(password=your_password, 
                    encrypted_seed=your_path_to_seed)
print(wallet.info)
```
