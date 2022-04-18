# wallet-seed-py
    Epic-Cash Wallet cryptography wrapped in Python:

    create() -> Create completely new epic-wallet insatnce
    from_bytes() -> Initialize epic-wallet from seed (bytes)
    from_mnemonic() -> Initialize epic-wallet from mnemonic seed-phrase (str)
    from_encrypted_seed() -> Initialize epic-wallet from previously encrypted seed (dict)
    get_tor_address() -> Generate onion TOR address for epic-wallet listener
    seed_as_str() -> Return wallet seed as string


## Packages
`pip install cryptography`

`pip install mnemonic`

## How to use
```
from seed import WalletSeed

your_password = "YOUR PASSWORD"
your_mnemonics = "YOUR MNEMONIC SEED PHRASE"


# Create new wallet:
wallet = WalletSeed(password=your_password)
print(wallet.info)


# Import wallet from mnemonic:
wallet = WalletSeed(mnemonics=your_mnemonics)
print(wallet.info)


# Import wallet from existing wallet.seed file:
encrypted_seed_dict = json.load(open('wallet.seed', 'r'))
wallet = WalletSeed(password=your_password, encrypted_seed=encrypted_seed_dict)
print(wallet.info)
```
