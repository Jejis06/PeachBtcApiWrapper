import requests as rq
import sys
import time
import itertools

import hashlib
import ecdsa
from ecdsa.keys import VerifyingKey

# --------- Compatibility patch for pgpy on python 3.13+ --------- 
try: 
    import imgdhr
except ImportError:
    import types
    fix_imghdr = types.ModuleType("imghdr")
    # hacky fix = just make it None
    fix_imghdr.what = lambda file, h=None: None
    sys.modules['imghdr'] = fix_imghdr

import pgpy


# Used only for testing the api veryfication system
from rich import inspect
from priv import pkey, pkeywall, unique_id, pubkeywall, pgp_passphrase_str, pgp_private_key_str, pgp_public_key_str
import json

# gl for erroro check

# TODO: 1) Implement the rest of endpoints               (_)
# TODO: 2) Authentication !!!!!!!!!!!                    (*)
# TODO: 2.1) Add token out off time functionality        (_)
# TODO: 3) Proper file structure for the wrapper         (_)
# TODO: 4) Better testing                                (_)


class PeachBTCError(Exception):
    def __init__(self, message: str, status_code: int = 999, err_id: str = ""):
        self.message: str = message
        self.status_code: int = status_code
        self.error_id: str = err_id
        super().__init__(self.message)

class PeachPaymentData():
    def __init__(self, payment_type: str, **required_fields: str):
        self.payment_type: str = payment_type
        self.payment_fields: dict[str, str]  = required_fields 


    def create_hash(self) -> tuple[str, dict[str, list[str]]]:
        hashed_values: list[str] = []
        for value in self.payment_fields.values():
            encoded_item = value.encode('utf-8')
            hashed_item: str = hashlib.sha256(encoded_item).hexdigest()

            hashed_values.append(hashed_item)

        return (self.payment_type, {"hashes":hashed_values})

class PeachMeansOfPayment():
    def __init__(self, payment_type: dict[str, list[str]]):
        self.payment_type: dict[str, list[str]] = payment_type

    def add_new_type(self, currency: str, payment_methods: list[str]):
        if currency in self.payment_type:
            self.payment_type[currency] = list(set(itertools.chain(self.payment_type[currency], payment_methods)))
        else:
            self.payment_type[currency].extend(payment_methods)

    def get(self):
        return self.payment_type
            


class PeachWrapper:
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


    # helper function to write acces token to query headers
    def __set_access_token(self) -> None:
        if self.access_token != '':
            self.session.headers.update({
                'Authorization': f'Bearer {self.access_token}'
            })

    def __send_request(self, method: str, suburl: str, data: dict = {} , params: dict = {}, requires_auth: bool = False) -> dict[str, int | float | str]:

        if requires_auth and not self.access_token:
            raise PeachBTCError("Access token required for this endpoint")

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

    def post_buy_offer(self, addressPrivateKey: str, releaseAddress: str, paymentData: list[PeachPaymentData], meansOfPayment: PeachMeansOfPayment, ammount_range: tuple[int, int], maxPremium: int|None = None):
        message: str = f"I confirm that only I, peach{self.user_id}, control the address {releaseAddress}"
        signature = self.__sign_message(message_to_sign=message, private_key_hex_arg=addressPrivateKey) [ 0 ]
        payments: dict[str, dict[str, list[str]]]= {}

        ammount_range:list[int] = [ammount_range[0], ammount_range[1]]

        for it in paymentData:
            paymentMethod, hashed_values = it.create_hash()
            payments[paymentMethod] = hashed_values 

        data = {
                'type' : 'bid',
                'amount': ammount_range,
                'meansOfPayment': meansOfPayment.get(),
                'paymentData': payments,
                'releaseAddress':releaseAddress,
                'messageSignature': signature,
                'maxPremium' : maxPremium 
                }

        return self.__send_request('POST', 'offer', data=data, requires_auth=True)
    
    def post_buy_offer(self, ammount: int, returnAddress: str, paymentData: list[PeachPaymentData], meansOfPayment: PeachMeansOfPayment, premium: int|None = None):
        payments: dict[str, dict[str, list[str]]]= {}

        for it in paymentData:
            paymentMethod, hashed_values = it.create_hash()
            payments[paymentMethod] = hashed_values 

        data = {
                'type': 'ask',
                'amount': ammount,
                'premium': premium,
                'meansOfPayment': meansOfPayment.get(),
                'paymentData': payments,
                'returnAddress': returnAddress
                }
        res = self.__send_request('POST', 'offer', data=data, requires_auth=True)
        return res




def main():
    peach: PeachWrapper = PeachWrapper(private_key_hex=pkey)
    res = peach.set_access_token(unique_id=unique_id, register=False)
    print(peach.system_status())
    #print(peach.info())
    #print(json.dumps(res, indent=4))
    #print(peach.access_token)
    #print(peach.private_key_hex, peach.user_id, peach.access_token, peach.expiry)
    #inspect(peach, methods=True, private=True)
    #inspect(peach.info())
    #print(json.dumps(peach.get_self_user(), indent=4))
    #peach.post_buy_offer((1,2))

    # TEST OF UPDATING THE PGP PUBLIC KEY
    # res = peach.update_self_user({
        # "pgpPublicKey": pgp_public_key_str,
        # "message": "Verifying my PGP key for Peach Bitcoin"
        # }, pgp_private_key=pgp_private_key_str, pgp_passphrase=pgp_passphrase_str)
    # print(res)

    #print(json.dumps(peach.get_self_user(), indent=4))

    # TEST OF SENDING A BUY OFFER
    #pmntd = [PeachPaymentData("paypal", phone="+111111111")]
    #mop = PeachMeansOfPayment({ "EUR": ["paypal"]})
    #print(peach.post_buy_offer(addressPrivateKey=pkeywall, releaseAddress=pubkeywall, paymentData=pmntd, meansOfPayment=mop, ammount_range=(20000,40000), maxPremium=0))

    #print(peach.get_own_offers())
    # print(peach.get_fee_estimates())
    #print(peach.get_self_payment_method_info())
    # print(peach.get_self_trading_limits())




    pass
if __name__ == '__main__':
    main()

