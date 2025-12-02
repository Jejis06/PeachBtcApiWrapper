# Peach Bitcoin API Wrapper

> ⚠️ **Note** - This is my personal project worked on in my free time. There may be bugs.

A comprehensive Python wrapper for the [Peach Bitcoin](https://peachbitcoin.com/) P2P trading API.

> **Based on the official Peach Bitcoin API Documentation**  
> https://docs.peachbitcoin.com/

## Features

- **Complete API Coverage**: All public and private endpoints implemented
- **Type Hints**: Full Python type annotations for IDE support
- **Auto Token Refresh**: Automatic handling of expired access tokens
- **Comprehensive Tests**: 139 tests (unit + integration)

## Installation

```bash
# Clone the repository
git clone https://github.com/Jejis06/PeachBtcApiWrapper.git
cd PeachBtcApiWrapper

# Create virtual environment
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Public Endpoints (No Authentication)

```python
from main import PeachWrapper

peach = PeachWrapper()

# Get market prices
prices = peach.market_prices()
print(f"BTC/EUR: {prices['EUR']}")

# Search for offers
offers = peach.search_offers(
    search_criteria={"type": "ask", "meansOfPayment": {"EUR": ["sepa"]}},
    filters={"sortBy": "lowestPremium", "size": 10}
)
```

### Private Endpoints (Authentication Required)

```python
from main import PeachWrapper, PeachPaymentData, PeachMeansOfPayment

# Initialize with your private key
peach = PeachWrapper(private_key_hex="your_64_char_hex_private_key")

# Authenticate
peach.set_access_token(unique_id="your_unique_device_id", register=False)

# Get your profile
user = peach.get_self_user()
print(f"Trades: {user['trades']}, Rating: {user['rating']}")

# Create a buy offer
payment_data = [PeachPaymentData("paypal", email="your@email.com")]
means = PeachMeansOfPayment({"EUR": ["paypal"]})

peach.post_buy_offer(
    addressPrivateKey="wallet_private_key",
    releaseAddress="bc1q...",
    paymentData=payment_data,
    meansOfPayment=means,
    amount_range=(50000, 100000),  # 50k-100k sats
    maxPremium=10  # Max 10% premium
)
```

## API Coverage

All endpoints from [docs.peachbitcoin.com](https://docs.peachbitcoin.com/) are implemented:

### Public Endpoints (15)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| System | `GET /v1/system/status` | `system_status()` |
| System | `GET /v1/info` | `info()` |
| System | `GET /v1/info/paymentMethods` | `payment_methods()` |
| Market | `GET /v1/market/price/:pair` | `market_price(pair)` |
| Market | `GET /v1/market/prices` | `market_prices()` |
| Market | `GET /v1/market/tradePricePeaks` | `ath_prices()` |
| Users | `GET /v1/user/:userId` | `get_user(userid)` |
| Users | `GET /v1/user/:userId/ratings` | `get_user_rating(userid)` |
| Users | `GET /v1/user/referral` | `check_referal_code(code)` |
| Offer | `GET /v1/offer/:offerId` | `get_offer_details(offerid)` |
| Offer | `POST /v1/offer/search` | `search_offers(criteria, filters)` |
| Contact | `POST /v1/contact/report` | `send_report(email, topic, reason, message)` |
| Blockchain | `GET /v1/tx/:txid` | `get_transaction_data(txid)` |
| Blockchain | `POST /v1/tx` | `post_transaction(tx_hex)` |
| Blockchain | `GET /v1/estimateFees` | `get_fee_estimates()` |

### Authentication Endpoints (2)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| Registration | `POST /v1/user/register` | `set_access_token(register=True)` |
| Authentication | `POST /v1/user/auth` | `set_access_token(register=False)` |

### Private User Endpoints (12)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| User (Private) | `GET /v1/user/me` | `get_self_user()` |
| User (Private) | `GET /v1/user/me/paymentMethods` | `get_self_payment_method_info()` |
| User (Private) | `GET /v1/user/tradingLimit` | `get_self_trading_limits()` |
| User (Private) | `PATCH /v1/user` | `update_self_user(data, pgp_key, passphrase)` |
| User (Private) | `GET /v1/user/:userId/status` | `get_user_status(userid)` |
| User (Private) | `PUT /v1/user/:userId/block` | `block_user(userid)` |
| User (Private) | `DELETE /v1/user/:userId/block` | `unblock_user(userid)` |
| User (Private) | `PATCH /v1/user/batching` | `user_manage_batching(enable)` |
| User (Private) | `PATCH /v1/user/referral/redeem/referralCode` | `user_redeem_referral_code(code)` |
| User (Private) | `PATCH /v1/user/referral/redeem/fiveFreeTrades` | `user_redeem_free_trades()` |
| User (Private) | `PATCH /v1/user/paymentHash` | `user_unlink_payment_hashes(hashes)` |
| User (Private) | `PATCH /v1/user/logout` | `logout()` |

### Private Offer Endpoints (14)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| Offer (Private) | `GET /v1/offer/:offerId/details` | `get_own_offer_details(offerid)` |
| Offer (Private) | `GET /v1/offers` | `get_own_offers()` |
| Offer (Private) | `GET /v1/offers/summary` | `get_own_offers_summaries()` |
| Offer (Private) | `POST /v1/offer` (bid) | `post_buy_offer(...)` |
| Offer (Private) | `POST /v1/offer` (ask) | `post_sell_offer(...)` |
| Offer (Private) | `POST /v1/offer/:offerId/escrow` | `create_escrow(offer_id, public_key)` |
| Offer (Private) | `GET /v1/offer/:offerId/escrow` | `get_funding_status(offer_id)` |
| Offer (Private) | `POST /v1/offer/:offerId/escrow/confirm` | `confirm_escrow_funding(offer_id)` |
| Offer (Private) | `PATCH /v1/offer/:offerId` (bid) | `update_buy_offer(...)` |
| Offer (Private) | `PATCH /v1/offer/:offerId` (ask) | `update_sell_offer(...)` |
| Offer (Private) | `POST /v1/offer/:offerId/cancel` | `cancel_offer(offer_id)` |
| Offer (Private) | `GET /v1/offer/:offerId/refundPsbt` | `get_refund_psbt(offer_id)` |
| Offer (Private) | `POST /v1/offer/:offerId/refund` | `refund_sell_offer(offer_id, tx)` |
| Offer (Private) | `POST /v1/offer/:offerId/revive` | `republish_sell_offer(offer_id)` |

### Private Match Endpoints (4)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| Match (Private) | `GET /v1/offer/:offerId/matches` | `get_matches(offer_id)` |
| Match (Private) | `POST /v1/offer/:offerId/match` | `match_sell_offer(...)` |
| Match (Private) | `POST /v1/offer/:offerId/match/undo` | `unmatch_sell_offer(offer_id, match_id)` |
| Match (Private) | `POST /v1/offer/:offerId/doublematch` | `doublematch_buy_offer(...)` |

### Private Contract Endpoints (16)

| Docs Section | Endpoint | Method |
|--------------|----------|--------|
| Contract (Private) | `GET /v1/contract/:contractId` | `get_contract_details(contract_id)` |
| Contract (Private) | `GET /v1/contracts/summary` | `get_contract_summaries()` |
| Contract (Private) | `GET /v1/contracts` | `get_contracts()` |
| Contract (Private) | `POST /v1/contract/:id/payment/confirm` | `confirm_payment_made(contract_id)` |
| Contract (Private) | `POST /v1/contract/:id/payment/received` | `confirm_payment_received(contract_id, tx)` |
| Contract (Private) | `POST /v1/contract/:id/rating` | `rate_counterparty(contract_id, rating, sig)` |
| Contract (Private) | `POST /v1/contract/:id/cancel` | `cancel_contract(contract_id, reason)` |
| Contract (Private) | `POST /v1/contract/:id/cancel/confirm` | `confirm_cancelation_request(contract_id)` |
| Contract (Private) | `POST /v1/contract/:id/cancel/reject` | `reject_cancelation_request(contract_id)` |
| Contract (Private) | `POST /v1/contract/:id/extend` | `extend_payment_time(contract_id)` |
| Contract (Private) | `GET /v1/contract/:id/chat` | `get_chat_log(contract_id, page)` |
| Contract (Private) | `POST /v1/contract/:id/chat` | `post_chat_message(contract_id, msg, sig)` |
| Contract (Private) | `POST /v1/contract/:id/chat/:msgId/read` | `set_chat_message_read(contract_id, msg_id)` |
| Contract (Private) | `POST /v1/contract/:id/dispute` | `raise_dispute(contract_id, reason, email)` |
| Contract (Private) | `POST /v1/contract/:id/dispute/acknowledge` | `acknowledge_dispute(contract_id)` |
| Contract (Private) | `POST /v1/contract/:id/dispute/outcome/acknowledge` | `acknowledge_dispute_outcome(contract_id)` |

**Total: 63 endpoints implemented**

## Testing

```bash
# Run unit tests (fast, no network required)
pytest test_peach_wrapper.py -v

# Run integration tests (requires priv.py with credentials)
pytest test_integration.py -v -s -m "not slow"

# Run all tests with coverage
pytest test_peach_wrapper.py test_integration.py -v --cov=main --cov-report=term-missing

# Include slow tests that create real offers (use with caution!)
pytest test_integration.py -v -s -m "slow"
```

## Testing Credentials Setup

To run integration tests with the real API, create a `priv.py` file (not tracked by git):

```python
# Your Peach account private key (64 hex characters)
pkey = "your_private_key_hex"

# Unique device identifier
unique_id = "your_unique_id"

# Wallet private key for signing release addresses
pkeywall = "wallet_private_key_hex"
pubkeywall = "bc1q..."  # Your Bitcoin address

# PGP keys 
with open("public_key.asc", "r") as f:
    pgp_public_key_str = f.read()
with open("private_key.asc", "r") as f:
    pgp_private_key_str = f.read()
with open("passphrase.txt", "r") as f:
    pgp_passphrase_str = f.read().strip()
```

> **Note**: This file is only required for running integration tests. The wrapper itself only needs a private key passed directly to `PeachWrapper()`.

## Project Structure

```
PeachBtcApiWrapper/
├── main.py                 # Main wrapper implementation
├── conftest.py             # Pytest configuration
├── test_peach_wrapper.py   # Unit tests (89 tests)
├── test_integration.py     # Integration tests (50 tests)
├── requirements.txt        # Python dependencies
├── priv.py                 # Created by you for testing 
└── README.md               # This file
```

## Documentation

This wrapper is implemented based on:

- **[Peach Bitcoin API Documentation](https://docs.peachbitcoin.com/)** - Official API reference
- **[Peach Under the Hood](https://peachbitcoin.com/blog/peach-under-the-hood/)** - Technical blog post explaining the trading flow

All endpoints and data structures follow the official documentation.

## License

MIT

## Disclaimer

This is an unofficial wrapper. Use at your own risk. The authors are not responsible for any financial losses incurred while using this software.

