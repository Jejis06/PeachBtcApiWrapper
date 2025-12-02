"""
Peach Bitcoin API Wrapper
=========================

A Python wrapper for the Peach Bitcoin P2P trading API.
Documentation: https://docs.peachbitcoin.com/

This wrapper provides a convenient interface for:
- Public market data (prices, offers, user ratings)
- Private user operations (authentication, profile management)
- Trading operations (buy/sell offers, matching, contracts)
- Contract management (payments, chat, disputes)

Usage:
    from main import PeachWrapper, PeachPaymentData, PeachMeansOfPayment
    
    # Initialize with private key for authentication
    peach = PeachWrapper(private_key_hex="your_64_char_hex_key")
    peach.set_access_token()
    
    # Get market prices
    prices = peach.market_prices()
    
    # Create a buy offer
    payment_data = [PeachPaymentData("paypal", email="your@email.com")]
    means = PeachMeansOfPayment({"EUR": ["paypal"]})
    peach.post_buy_offer(
        addressPrivateKey="wallet_private_key",
        releaseAddress="your_btc_address",
        paymentData=payment_data,
        meansOfPayment=means,
        amount_range=(50000, 100000)
    )
"""

import requests as rq
import sys
import time
import itertools
import hashlib
import ecdsa
from ecdsa.keys import VerifyingKey

# --------- Compatibility patch for pgpy on Python 3.13+ --------- 
try: 
    import imghdr
except ImportError:
    import types
    fix_imghdr = types.ModuleType("imghdr")
    fix_imghdr.what = lambda file, h=None: None
    sys.modules['imghdr'] = fix_imghdr

import pgpy


class PeachBTCError(Exception):
    """Exception raised for Peach Bitcoin API errors.
    
    Attributes:
        message: Human-readable error description
        status_code: HTTP status code (999 for non-HTTP errors)
        error_id: API-specific error identifier
    """
    def __init__(self, message: str, status_code: int = 999, err_id: str = ""):
        self.message: str = message
        self.status_code: int = status_code
        self.error_id: str = err_id
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"PeachBTCError(message={self.message!r}, status_code={self.status_code}, error_id={self.error_id!r})"


class PeachPaymentData:
    """Container for payment method data with automatic hashing.
    
    Payment data is hashed before being sent to the API for privacy.
    
    Example:
        >>> pd = PeachPaymentData("paypal", email="user@example.com", phone="+123456789")
        >>> payment_type, hashes = pd.create_hash()
    """
    def __init__(self, payment_type: str, **required_fields: str):
        """Initialize payment data.
        
        Args:
            payment_type: Payment method ID (e.g., 'paypal', 'sepa', 'revolut')
            **required_fields: Payment-specific fields (e.g., email, iban, phone)
        """
        self.payment_type: str = payment_type
        self.payment_fields: dict[str, str] = required_fields 

    def create_hash(self) -> tuple[str, dict[str, list[str]]]:
        """Create SHA256 hashes of payment field values.
        
        Returns:
            Tuple of (payment_type, {"hashes": [list of hashed values]})
        """
        hashed_values: list[str] = []
        for value in self.payment_fields.values():
            encoded_item = value.encode('utf-8')
            hashed_item: str = hashlib.sha256(encoded_item).hexdigest()
            hashed_values.append(hashed_item)

        return (self.payment_type, {"hashes": hashed_values})

    def __repr__(self) -> str:
        return f"PeachPaymentData(payment_type={self.payment_type!r}, fields={list(self.payment_fields.keys())})"


class PeachMeansOfPayment:
    """Container for accepted payment methods grouped by currency.
    
    Example:
        >>> mop = PeachMeansOfPayment({"EUR": ["sepa", "paypal"], "CHF": ["twint"]})
        >>> mop.add_new_type("GBP", ["revolut"])
        >>> mop.get()
        {'EUR': ['sepa', 'paypal'], 'CHF': ['twint'], 'GBP': ['revolut']}
    """
    def __init__(self, payment_type: dict[str, list[str]]):
        """Initialize means of payment.
        
        Args:
            payment_type: Dictionary mapping currency codes to payment method lists
        """
        self.payment_type: dict[str, list[str]] = payment_type

    def add_new_type(self, currency: str, payment_methods: list[str]):
        """Add or extend payment methods for a currency.
        
        Args:
            currency: Currency code (e.g., 'EUR', 'USD')
            payment_methods: List of payment method IDs to add
        """
        if currency in self.payment_type:
            self.payment_type[currency] = list(set(itertools.chain(self.payment_type[currency], payment_methods)))
        else:
            self.payment_type[currency] = payment_methods

    def get(self) -> dict[str, list[str]]:
        """Get the payment methods dictionary."""
        return self.payment_type

    def __repr__(self) -> str:
        return f"PeachMeansOfPayment({self.payment_type})"
            


class PeachWrapper:
    """Main client for the Peach Bitcoin API.
    
    Provides access to all public and private API endpoints.
    
    Public endpoints (no authentication required):
        - System info, status, payment methods
        - Market prices
        - Public user profiles and ratings
        - Offer search
        - Blockchain data
    
    Private endpoints (authentication required):
        - User management
        - Buy/sell offers
        - Matching
        - Contract management
        - Chat and disputes
    
    Example:
        >>> peach = PeachWrapper(private_key_hex="your_hex_private_key")
        >>> peach.set_access_token()  # Authenticate
        >>> print(peach.market_prices())
        >>> print(peach.get_self_user())
    """
    def __init__(self, access_token: str = "", private_key_hex: str = ""):
        # User information
        self.private_key_hex: str = private_key_hex

        # Peach information
        self.version: str = 'v1'
        self.base_url: str = "https://api.peachbitcoin.com"
        self.access_token: str = access_token
        self.expiry: int = -1
        self.user_id: str = "" 

        self.session: rq.Session = rq.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'PeachBitcoin-Python-Wrapper/1.0'
        })

        # set access token (encrypted private key)
        self.__set_access_token()

    # Authentication / core signing functionality

    def get_own_user_id(self) -> str:
        return self.get_public_key() 

    def get_public_key(self, curve: ecdsa.curves.Curve = ecdsa.SECP256k1) -> str:
        try:
            private_key_bytes: bytes = bytes.fromhex(self.private_key_hex)
            signing_key: ecdsa.SigningKey = ecdsa.SigningKey.from_string(private_key_bytes, curve=curve)
        except Exception as e:
            raise PeachBTCError(f"Error: Invalid private key. Make sure it's a 64-char hex string. {e}")

        veryfying_key: VerifyingKey = signing_key.get_verifying_key()
        return str(veryfying_key.to_string("compressed").hex())

    def __set_new_private_key(self, new_key: str) -> None:
        self.private_key_hex = new_key
        return None

    def __sign_message_pgp(self, message_to_sign: str, private_key_str: str, passphrase: str | None = None) -> str:
        try:
            priv_key, _ = pgpy.PGPKey.from_blob(private_key_str)

            message = pgpy.PGPMessage.new(message_to_sign)
            if passphrase and priv_key.is_protected:
                with priv_key.unlock(passphrase):
                    signature: str = str(priv_key.sign(message))
            else:
                signature: str = str(priv_key.sign(message))

            return signature
        except Exception as e:
            raise PeachBTCError(f"PGP Signing Error: {e}")


    def __sign_message(self, message_to_sign: str, private_key_hex_arg: str = "", hashfunc: "hashlib._Hash" = hashlib.sha256, curve: ecdsa.curves.Curve = ecdsa.SECP256k1)-> tuple[str, str]:
        if self.private_key_hex == '' and private_key_hex_arg == '':
            raise PeachBTCError("No private key provided")

        private_key = self.private_key_hex if (private_key_hex_arg == "") else private_key_hex_arg

        try:
            private_key_bytes: bytes = bytes.fromhex(private_key)
            signing_key: ecdsa.SigningKey = ecdsa.SigningKey.from_string(private_key_bytes, curve=curve)
        except Exception as e:
            raise PeachBTCError(f"Error: Invalid private key. Make sure it's a 64-char hex string. {e}")

        veryfying_key: VerifyingKey = signing_key.get_verifying_key()
        public_key: str = veryfying_key.to_string("compressed").hex()

        try:
            signature_bytes = signing_key.sign(
                    message_to_sign.encode('utf-8'),
                    hashfunc = hashfunc 
            )
            signature_hex:str = signature_bytes.hex()
        except Exception as e:
            raise PeachBTCError(f"Error during message signing: {e}")

        return (signature_hex, public_key)



    def set_access_token(self, private_key_hex: str | None = None, unique_id:str | None = None, register: bool = True):
        if register:
            url = "user/register" 
        else: url = "user/auth"
        if private_key_hex is None:
            private_key_hex = self.private_key_hex


        timestamp = int(time.time() * 1000)
        message_to_sign = f"Peach Registration {timestamp}"
        signature_hex, public_key = self.__sign_message(message_to_sign, private_key_hex)

        data = {
                "publicKey": public_key,
                "message" : message_to_sign,
                "signature": signature_hex
        }

        if unique_id is not None: data["uniqueId"] = unique_id
        resp = self.__send_request('POST', url, data)

        if "error" in resp:
            raise PeachBTCError(f"{resp['error']}")


        self.access_token = str(resp['accessToken'])
        self.expiry = int(resp['expiry'])

        self.__set_access_token() 
        self.user_id = public_key 
        self.private_key_hex = private_key_hex

        return resp


    # helper function to write access token to query headers
    def __set_access_token(self) -> None:
        if self.access_token != '':
            self.session.headers.update({
                'Authorization': f'Bearer {self.access_token}'
            })

    def is_token_expired(self) -> bool:
        """Check if the current access token has expired."""
        if self.expiry == -1:
            return True
        current_time = int(time.time() * 1000)
        return current_time >= self.expiry

    def refresh_token_if_expired(self) -> bool:
        """Refresh the access token if it has expired.
        
        Returns:
            True if token was refreshed, False if still valid
        """
        if self.is_token_expired():
            if self.private_key_hex:
                self.set_access_token(register=False)
                return True
            else:
                raise PeachBTCError("Token expired and no private key available for refresh")
        return False

    def get_token_expiry_time(self) -> int:
        """Get the remaining time until token expires in milliseconds."""
        if self.expiry == -1:
            return 0
        current_time = int(time.time() * 1000)
        remaining = self.expiry - current_time
        return max(0, remaining)

    def __send_request(self, method: str, suburl: str, data: dict = {}, params: dict = {}, requires_auth: bool = False) -> dict[str, int | float | str]:

        if requires_auth:
            if not self.access_token:
                raise PeachBTCError("Access token required for this endpoint")
            # Auto-refresh token if expired
            if self.is_token_expired() and self.private_key_hex:
                self.refresh_token_if_expired()

        try:
            if method.upper() not in ['PATCH', 'GET', 'POST', 'PUT', 'DELETE']:
                raise ValueError(f"Unsupported HTTP method: {method}")
            if method.upper() in ['POST', 'PUT', 'PATCH'] :
                resp = self.session.request(method, f"{self.base_url}/{self.version}/{suburl}", json=data, params=params)
            else:
                resp = self.session.request(method, f"{self.base_url}/{self.version}/{suburl}", params=params)



            if not resp.ok:
                try:
                    error_data: dict[str, str] = resp.json()
                    error_message: str = error_data.get('error', f'HTTP {resp.status_code}')
                    error_id: str = error_data.get('id', '')
                except:
                    error_message = f'HTTP {resp.status_code}: {resp.text}'
                    error_id = '' 
                
                    raise PeachBTCError(error_message, resp.status_code, error_id)

            return resp.json()

        except rq.RequestException as e:
            raise PeachBTCError(f"Request failed: {str(e)}")

    # Public endpoints

    # System endpoints 
    def system_status(self):
        resp = self.__send_request('GET', 'system/status')
        return resp 
       
    def info(self):
        resp = self.__send_request('GET', 'info')
        return resp

    def payment_methods(self):
        resp = self.__send_request('GET', 'info/paymentMethods')
        return resp

    # Public market endpoints 
    def market_price(self, pair: str):
        resp = self.__send_request('GET', f'market/price/{pair}')
        return resp

    def market_prices(self):
        resp = self.__send_request('GET', 'market/prices')
        return resp

    def ath_prices(self):
        resp = self.__send_request('GET','market/tradePricePeaks')
        return resp

    # Public user endpoints
    def get_user(self, userid: str):
        # userid = public key
        resp = self.__send_request('GET', f'user/{userid}')
        return resp

    def get_user_rating(self, userid: str):
        resp = self.__send_request('GET', f'user/{userid}/ratings')
        return resp

    def check_referal_code(self, code: str):
        params = {"code": code}
        resp = self.__send_request('GET', f'user/referral', params=params)
        return resp

    # Public offer endpoints
    def get_offer_details(self, offerid: str):
        resp = self.__send_request('GET', f'offer/{offerid}', requires_auth=True)
        return resp

    def search_offers(self, search_criteria: dict, filters: dict):
        resp = self.__send_request('POST', 'offer/search', data=search_criteria, params=filters)
        return resp

    # Public contact endpoints
    def send_report(self, email: str, topic: str, reason: str, message: str):
        data = {
                "email": email,
                "topic": topic,
                "reason": reason,
                "message": message
        }
        resp = self.__send_request('POST', 'contact/report', data=data)
        return resp

    # Public blockchain endpoints
    def get_transaction_data(self, txid: str):
        resp = self.__send_request('GET', f'tx/{txid}')
        return resp

    def post_transaction(self, tx_hex: str):
        data = {
                'tx': tx_hex
        }
        resp = self.__send_request('POST', 'tx', data=data)
        return resp
    
    def get_fee_estimates(self):
        resp = self.__send_request('GET', 'estimateFees')
        return resp

    # Private endpoints

    # Private user endpoints
    def get_self_user(self):
        resp = self.__send_request('GET', 'user/me', requires_auth=True)
        return resp

    def get_self_payment_method_info(self):
        resp = self.__send_request('GET', 'user/me/paymentMethods', requires_auth=True)
        return resp

    def get_self_trading_limits(self):
        resp = self.__send_request('GET', 'user/tradingLimit', requires_auth=True)
        return resp

    def update_self_user(self, data: dict[str, str | int], pgp_private_key: str | None = None, pgp_passphrase: str | None = None):

        if "pgpPublicKey" in data:
            if "message" not in data:
                raise PeachBTCError("If pgpPublicKey is passed, a 'message' string to be signed is required in data.")
            elif pgp_private_key is None:
                raise PeachBTCError("If pgpPublicKey is passed, the corresponding PGP private key is required to sign the proof message.")

            signature, _ = self.__sign_message(str( data['pgpPublicKey'] ))
            print(signature)
            pgpsignature = self.__sign_message_pgp(str( data['message'] ), pgp_private_key, pgp_passphrase)


            data['signature'] = signature
            data['pgpSignature'] = pgpsignature


        resp = self.__send_request('PATCH', 'user', data=data, requires_auth=True)
        return resp

    def get_user_status(self, userid: str):
        resp = self.__send_request('GET', f'user/{userid}/status', requires_auth=True)
        return resp

    def block_user(self, userid: str):
        resp = self.__send_request('PUT', f'user/{userid}/block', requires_auth=True)
        return resp
    
    def unblock_user(self, userid: str):
        resp = self.__send_request('DELETE', f'user/{userid}/block', requires_auth=True)
        return resp

    def user_manage_batching(self, enable: bool):
        resp = self.__send_request('PATCH', 'user/batching', data={"enableBatching" : enable}, requires_auth=True)
        return resp

    def user_redeem_referral_code(self, code: str):
        resp = self.__send_request('PATCH', 'user/referral/redeem/referralCode', data={"code": code}, requires_auth=True)
        return resp

    def user_redeem_free_trades(self):
        resp = self.__send_request('PATCH', 'user/referral/redeem/fiveFreeTrades', requires_auth=True)
        return resp

    def user_unlink_payment_hashes(self, hashes: list[str]):
        resp = self.__send_request('PATCH', 'user/paymentHash', data={"hashes":hashes}, requires_auth=True)
        return resp

    def logout(self):
        resp = self.__send_request('PATCH', 'user/logout', requires_auth=True)
        return resp


    # Private offer endpoints
    def get_own_offer_details(self, offerid: str):
        resp = self.__send_request('GET', f'offer/{offerid}/details', requires_auth=True)
        return resp

    def get_own_offers(self):
        resp = self.__send_request('GET', 'offers', requires_auth=True)
        return resp

    def get_own_offers_summaries(self):
        resp = self.__send_request('GET', 'offers/summary', requires_auth=True)
        return resp

    def post_buy_offer(self, addressPrivateKey: str, releaseAddress: str, paymentData: list[PeachPaymentData], meansOfPayment: PeachMeansOfPayment, amount_range: tuple[int, int], maxPremium: int | None = None):
        """Post a buy offer (bid) to the market.
        
        Args:
            addressPrivateKey: Private key for the release address
            releaseAddress: Bitcoin address to receive purchased BTC
            paymentData: List of payment data with hashed values
            meansOfPayment: Accepted payment methods per currency
            amount_range: Tuple of (min, max) amount in satoshis
            maxPremium: Maximum premium percentage willing to pay (optional)
        """
        message: str = f"I confirm that only I, peach{self.user_id}, control the address {releaseAddress}"
        signature = self.__sign_message(message_to_sign=message, private_key_hex_arg=addressPrivateKey)[0]
        payments: dict[str, dict[str, list[str]]] = {}

        amount_list: list[int] = [amount_range[0], amount_range[1]]

        for it in paymentData:
            paymentMethod, hashed_values = it.create_hash()
            payments[paymentMethod] = hashed_values 

        data = {
            'type': 'bid',
            'amount': amount_list,
                'meansOfPayment': meansOfPayment.get(),
                'paymentData': payments,
            'releaseAddress': releaseAddress,
                'messageSignature': signature,
            'maxPremium': maxPremium 
                }

        return self.__send_request('POST', 'offer', data=data, requires_auth=True)
    
    def post_sell_offer(self, amount: int, returnAddress: str, paymentData: list[PeachPaymentData], meansOfPayment: PeachMeansOfPayment, premium: int | None = None):
        """Post a sell offer (ask) to the market.
        
        Args:
            amount: Amount in satoshis to sell
            returnAddress: Bitcoin address for refund if trade fails
            paymentData: List of payment data with hashed values
            meansOfPayment: Accepted payment methods per currency
            premium: Premium percentage (optional)
        """
        payments: dict[str, dict[str, list[str]]] = {}

        for it in paymentData:
            paymentMethod, hashed_values = it.create_hash()
            payments[paymentMethod] = hashed_values 

        data = {
                'type': 'ask',
                'amount': amount,
                'premium': premium,
                'meansOfPayment': meansOfPayment.get(),
                'paymentData': payments,
                'returnAddress': returnAddress
                }
        return self.__send_request('POST', 'offer', data=data, requires_auth=True)

    def create_escrow(self, offer_id: str, public_key: str):
        """Create an escrow for a sell offer.
        
        Args:
            offer_id: The ID of the sell offer
            public_key: The public key for the escrow
        """
        data = {'publicKey': public_key}
        return self.__send_request('POST', f'offer/{offer_id}/escrow', data=data, requires_auth=True)

    def get_funding_status(self, offer_id: str):
        """Get the funding status of an escrow.
        
        Args:
            offer_id: The ID of the sell offer
        """
        return self.__send_request('GET', f'offer/{offer_id}/escrow', requires_auth=True)

    def confirm_escrow_funding(self, offer_id: str):
        """Confirm that the escrow has been funded.
        
        Args:
            offer_id: The ID of the sell offer
        """
        return self.__send_request('POST', f'offer/{offer_id}/escrow/confirm', requires_auth=True)

    def update_buy_offer(self, offer_id: str, amount_range: tuple[int, int] | None = None, 
                         means_of_payment: PeachMeansOfPayment | None = None,
                         payment_data: list[PeachPaymentData] | None = None,
                         max_premium: int | None = None):
        """Update an existing buy offer.
        
        Args:
            offer_id: The ID of the buy offer to update
            amount_range: New amount range (min, max) in satoshis
            means_of_payment: New payment methods
            payment_data: New payment data
            max_premium: New maximum premium percentage
        """
        data: dict = {}
        
        if amount_range is not None:
            data['amount'] = [amount_range[0], amount_range[1]]
        if means_of_payment is not None:
            data['meansOfPayment'] = means_of_payment.get()
        if payment_data is not None:
            payments: dict[str, dict[str, list[str]]] = {}
            for it in payment_data:
                paymentMethod, hashed_values = it.create_hash()
                payments[paymentMethod] = hashed_values
            data['paymentData'] = payments
        if max_premium is not None:
            data['maxPremium'] = max_premium
            
        return self.__send_request('PATCH', f'offer/{offer_id}', data=data, requires_auth=True)

    def update_sell_offer(self, offer_id: str, amount: int | None = None,
                          means_of_payment: PeachMeansOfPayment | None = None,
                          payment_data: list[PeachPaymentData] | None = None,
                          premium: int | None = None):
        """Update an existing sell offer.
        
        Args:
            offer_id: The ID of the sell offer to update
            amount: New amount in satoshis
            means_of_payment: New payment methods
            payment_data: New payment data
            premium: New premium percentage
        """
        data: dict = {}
        
        if amount is not None:
            data['amount'] = amount
        if means_of_payment is not None:
            data['meansOfPayment'] = means_of_payment.get()
        if payment_data is not None:
            payments: dict[str, dict[str, list[str]]] = {}
            for it in payment_data:
                paymentMethod, hashed_values = it.create_hash()
                payments[paymentMethod] = hashed_values
            data['paymentData'] = payments
        if premium is not None:
            data['premium'] = premium
            
        return self.__send_request('PATCH', f'offer/{offer_id}', data=data, requires_auth=True)

    def cancel_offer(self, offer_id: str):
        """Cancel an existing offer.
        
        Args:
            offer_id: The ID of the offer to cancel
        """
        return self.__send_request('POST', f'offer/{offer_id}/cancel', requires_auth=True)

    def get_refund_psbt(self, offer_id: str):
        """Get a PSBT for refunding a sell offer.
        
        Args:
            offer_id: The ID of the sell offer
        """
        return self.__send_request('GET', f'offer/{offer_id}/refundPsbt', requires_auth=True)

    def refund_sell_offer(self, offer_id: str, tx: str):
        """Submit a signed refund transaction for a sell offer.
        
        Args:
            offer_id: The ID of the sell offer
            tx: The signed transaction hex
        """
        data = {'tx': tx}
        return self.__send_request('POST', f'offer/{offer_id}/refund', data=data, requires_auth=True)

    def republish_sell_offer(self, offer_id: str):
        """Re-publish a sell offer that was previously taken offline.
        
        Args:
            offer_id: The ID of the sell offer to republish
        """
        return self.__send_request('POST', f'offer/{offer_id}/revive', requires_auth=True)

    # Private match endpoints
    
    def get_matches(self, offer_id: str):
        """Get all matches for an offer.
        
        Args:
            offer_id: The ID of the offer
        """
        return self.__send_request('GET', f'offer/{offer_id}/matches', requires_auth=True)

    def match_sell_offer(self, offer_id: str, match_offer_id: str, 
                         price: float, currency: str, payment_method: str,
                         symmetric_key_encrypted: str, symmetric_key_signature: str,
                         payment_data_encrypted: str, payment_data_signature: str):
        """Match a sell offer with a buy offer.
        
        Args:
            offer_id: The ID of your sell offer
            match_offer_id: The ID of the buy offer to match with
            price: Agreed price
            currency: Currency code (e.g., 'EUR')
            payment_method: Payment method ID
            symmetric_key_encrypted: Encrypted symmetric key for the buyer
            symmetric_key_signature: Signature of the symmetric key
            payment_data_encrypted: Encrypted payment data
            payment_data_signature: Signature of the payment data
        """
        data = {
            'matchingOfferId': match_offer_id,
            'price': price,
            'currency': currency,
            'paymentMethod': payment_method,
            'symmetricKeyEncrypted': symmetric_key_encrypted,
            'symmetricKeySignature': symmetric_key_signature,
            'paymentDataEncrypted': payment_data_encrypted,
            'paymentDataSignature': payment_data_signature
        }
        return self.__send_request('POST', f'offer/{offer_id}/match', data=data, requires_auth=True)

    def unmatch_sell_offer(self, offer_id: str, match_offer_id: str):
        """Unmatch a previously matched sell offer.
        
        Args:
            offer_id: The ID of your sell offer
            match_offer_id: The ID of the matched buy offer to unmatch
        """
        data = {'matchingOfferId': match_offer_id}
        return self.__send_request('POST', f'offer/{offer_id}/match/undo', data=data, requires_auth=True)

    def doublematch_buy_offer(self, offer_id: str, match_offer_id: str,
                              currency: str, payment_method: str,
                              symmetric_key_encrypted: str, symmetric_key_signature: str,
                              payment_data_encrypted: str, payment_data_signature: str):
        """Double match a buy offer (confirm match from buyer side).
        
        Args:
            offer_id: The ID of your buy offer
            match_offer_id: The ID of the sell offer that matched you
            currency: Currency code (e.g., 'EUR')
            payment_method: Payment method ID
            symmetric_key_encrypted: Encrypted symmetric key for the seller
            symmetric_key_signature: Signature of the symmetric key
            payment_data_encrypted: Encrypted payment data
            payment_data_signature: Signature of the payment data
        """
        data = {
            'matchingOfferId': match_offer_id,
            'currency': currency,
            'paymentMethod': payment_method,
            'symmetricKeyEncrypted': symmetric_key_encrypted,
            'symmetricKeySignature': symmetric_key_signature,
            'paymentDataEncrypted': payment_data_encrypted,
            'paymentDataSignature': payment_data_signature
        }
        return self.__send_request('POST', f'offer/{offer_id}/doublematch', data=data, requires_auth=True)

    # Private contract endpoints
    
    def get_contract_details(self, contract_id: str):
        """Get details of a specific contract.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('GET', f'contract/{contract_id}', requires_auth=True)

    def get_contract_summaries(self):
        """Get summaries of all contracts."""
        return self.__send_request('GET', 'contracts/summary', requires_auth=True)

    def get_contracts(self):
        """Get all contracts.
        
        Note: This endpoint may not be available on all API versions.
        If it returns 404, use get_contract_summaries() instead and
        then get_contract_details() for individual contracts.
        """
        return self.__send_request('GET', 'contracts', requires_auth=True)

    def confirm_payment_made(self, contract_id: str):
        """Confirm that payment has been sent (buyer action).
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/payment/confirm', requires_auth=True)

    def confirm_payment_received(self, contract_id: str, release_transaction: str | None = None):
        """Confirm that payment has been received and release Bitcoin (seller action).
        
        According to the Peach flow, the seller receives a PSBT from the API,
        signs it with their escrow key, and submits the fully signed transaction
        to release the Bitcoin to the buyer.
        
        Args:
            contract_id: The ID of the contract
            release_transaction: The fully signed release transaction hex (optional,
                                 required to release Bitcoin from escrow)
        """
        data = {}
        if release_transaction is not None:
            data['releaseTransaction'] = release_transaction
        return self.__send_request('POST', f'contract/{contract_id}/payment/confirm', data=data, requires_auth=True)

    def rate_counterparty(self, contract_id: str, rating: int, signature: str):
        """Rate the counterparty after a completed trade.
        
        Args:
            contract_id: The ID of the contract
            rating: Rating value (1-5 or as defined by API)
            signature: Signature proving the rating
        """
        data = {
            'rating': rating,
            'signature': signature
        }
        return self.__send_request('POST', f'contract/{contract_id}/rating', data=data, requires_auth=True)

    def cancel_contract(self, contract_id: str, reason: str | None = None):
        """Request to cancel a contract.
        
        Args:
            contract_id: The ID of the contract
            reason: Optional reason for cancellation
        """
        data = {}
        if reason is not None:
            data['reason'] = reason
        return self.__send_request('POST', f'contract/{contract_id}/cancel', data=data, requires_auth=True)

    def confirm_cancelation_request(self, contract_id: str):
        """Confirm/accept a cancellation request from counterparty.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/cancel/confirm', requires_auth=True)

    def reject_cancelation_request(self, contract_id: str):
        """Reject a cancellation request from counterparty.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/cancel/reject', requires_auth=True)

    def extend_payment_time(self, contract_id: str):
        """Extend the payment deadline for a contract.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/extend', requires_auth=True)

    # Contract chat endpoints
    
    def get_chat_log(self, contract_id: str, page: int = 0):
        """Get the chat log for a contract.
        
        Args:
            contract_id: The ID of the contract
            page: Page number for pagination (default 0)
        """
        params = {'page': page}
        return self.__send_request('GET', f'contract/{contract_id}/chat', params=params, requires_auth=True)

    def post_chat_message(self, contract_id: str, message: str, signature: str):
        """Send a chat message in a contract.
        
        Args:
            contract_id: The ID of the contract
            message: The encrypted message content
            signature: Signature of the message
        """
        data = {
            'message': message,
            'signature': signature
        }
        return self.__send_request('POST', f'contract/{contract_id}/chat', data=data, requires_auth=True)

    def set_chat_message_read(self, contract_id: str, message_id: str):
        """Mark a chat message as read.
        
        Args:
            contract_id: The ID of the contract
            message_id: The ID of the message to mark as read
        """
        return self.__send_request('POST', f'contract/{contract_id}/chat/{message_id}/read', requires_auth=True)

    # Contract dispute endpoints
    
    def raise_dispute(self, contract_id: str, reason: str, email: str | None = None):
        """Raise a dispute for a contract.
        
        Args:
            contract_id: The ID of the contract
            reason: The reason for the dispute
            email: Optional email for dispute communication
        """
        data = {'reason': reason}
        if email is not None:
            data['email'] = email
        return self.__send_request('POST', f'contract/{contract_id}/dispute', data=data, requires_auth=True)

    def acknowledge_dispute(self, contract_id: str):
        """Acknowledge that a dispute has been raised against you.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/dispute/acknowledge', requires_auth=True)

    def acknowledge_dispute_outcome(self, contract_id: str):
        """Acknowledge the outcome of a dispute resolution.
        
        Args:
            contract_id: The ID of the contract
        """
        return self.__send_request('POST', f'contract/{contract_id}/dispute/outcome/acknowledge', requires_auth=True)




def main():
    """Demo function showing basic usage of the wrapper."""
    import json
    
    peach = PeachWrapper()
    
    print("=== Peach Bitcoin API Wrapper Demo ===\n")
    
    # Test public endpoints
    print("1. System Status:")
    print(json.dumps(peach.system_status(), indent=2))
    
    print("\n2. Market Prices:")
    print(json.dumps(peach.market_prices(), indent=2))
    
    print("\n3. Fee Estimates:")
    print(json.dumps(peach.get_fee_estimates(), indent=2))
    
    # For authenticated endpoints, uncomment and configure:
    # peach = PeachWrapper(private_key_hex=...)
    # peach.set_access_token(unique_id=..., register=...)
    # print(json.dumps(peach.get_self_user(), indent=2))


if __name__ == '__main__':
    main()

