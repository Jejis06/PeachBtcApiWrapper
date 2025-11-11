import requests as rq
import time
import hashlib
import ecdsa
from ecdsa.keys import VerifyingKey

# Used only for testing the api veryfication system
from priv import pkey, unique_id
import json
# gl for erroro check


# TODO: 1) Implement the rest of endpoints               (_)
# TODO: 2) Authentication !!!!!!!!!!!                    (*)
# TODO: 3) Proper file structure for the wrapper         (_)
# TODO: 4) Better testing                                (_)

class PeachBTCError(Exception):
    def __init__(self, message: str, status_code: int = 999, err_id: str = ""):
        self.message: str = message
        self.status_code: int = status_code
        self.error_id: str = err_id
        super().__init__(self.message)


class PeachWrapper:
    def __init__(self, access_token: str = ""):


        # Peach information
        self.version: str = 'v1'
        self.base_url: str = "https://api.peachbitcoin.com"
        self.access_token: str = access_token
        self.expiry: int = -1

        self.session: rq.Session = rq.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'PeachBitcoin-Python-Wrapper/1.0'
        })

        # set access token (encrypted private key)
        self.__set_access_token()
        pass

    # Authentication


    def set_access_token(self, private_key_hex: str, unique_id:str | None = None, register: bool = True):
        if register:
            url = "user/register" 
        else: url = "user/auth"

        try:
            private_key_bytes = bytes.fromhex(private_key_hex)
            signing_key: ecdsa.SigningKey = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        except Exception as e:
            raise PeachBTCError(f"Error: Invalid private key. Make sure it's a 64-char hex string. {e}")

        veryfying_key: VerifyingKey = signing_key.get_verifying_key()
        public_key: str = veryfying_key.to_string("compressed").hex()

        timestamp = int(time.time() * 1000)
        message_to_sign = f"Peach Registration {timestamp}"

        try:
            signature_bytes = signing_key.sign(
                    message_to_sign.encode('utf-8'),
                    hashfunc = hashlib.sha256
            )
            signature_hex = signature_bytes.hex()
        except Exception as e:
            raise PeachBTCError(f"Error during message signing: {e}")


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
        pass


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
            if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE']:
                raise ValueError(f"Unsupported HTTP method: {method}")
            if method.upper() in ['POST', 'PUT'] :
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
        resp = self.__send_request('GET', 'system/info')
        return resp

    def payment_methods(self):
        resp = self.__send_request('GET', 'system/info/paymentMethods')
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

    def update_self_user(self, data: dict[str, str | int]):
        if "pgpPublicKey" in data:
            if "message" not in data:
                raise PeachBTCError("If pgppublickey passed 'message' to be signed with secret PGP keys is required")
            elif "pgpSignature" not in data:
                raise PeachBTCError("If pgppublickey passed 'pgpSignature' for message is required")
            elif "signature" not in data:
                raise PeachBTCError("If pgppublickey passed 'signature' by the Peach account of the new pgpPublicKey as message is required")

        resp = self.__send_request('PATCH', 'user', data=data, requires_auth=True)
        return resp




# TESTS
def test_system(peach: PeachWrapper):
    print("INFO ---- ")
    print(peach.info())

    print("PAYMENT METHODS ---- ")
    print(peach.payment_methods())

    print("SYSTEM STATUS ---- ")
    print(peach.system_status())
    pass

def test_market(peach: PeachWrapper):
    print("MARKET PRICES ---- ")
    print(peach.market_prices())

    print("MARKET PRICE BTCEUR ---- ")
    print(peach.market_price("BTCEUR"))
    
    print("ATH PRICES---- ")
    print(peach.ath_prices())
    pass

def test_user(peach: PeachWrapper):
    user = ("03870fb8d201672926c247e9f98ba43620db1695ed57e9c098f9988a58485a2565") # public key
    print("GET USER ---- ")
    print(peach.get_user(user))

    print("GET USER RATING---- ")
    print(peach.get_user_rating(user))

    print("CHECK REFERAL CODE---- ")
    print(peach.check_referal_code("SATOSHI"))
    pass

def test_offer(peach: PeachWrapper):
    print("GET OFFER DETAILS---- ")
    print(peach.get_offer_details("114"))
    print("SEARCH OFFERS---- ")
    print(peach.search_offers({
      #"type": "", bid or ask
      #"amount": [30000, 2000000],
      #"meansOfPayment": { "EUR": ["sepa"] },
      #"maxPremium": 10,
      #"minReputation": 0.5
    }, {
        "sortBy":"lowestPremium"

    }))

    pass

def test_offer_private(peach: PeachWrapper):

    offers = (peach.search_offers({
      #"type": "", bid or ask
      #"amount": [30000, 2000000],
      #"meansOfPayment": { "EUR": ["sepa"] },
      #"maxPremium": 10,
      #"minReputation": 0.5
    }, {
        "sortBy":"lowestPremium"

    }))

    offer: dict[str, str] = offers['offers'][0]
    id = offer['id']

    offer = peach.get_offer_details(id)
    print(json.dumps(offer, indent=4))





def main():
    peach: PeachWrapper = PeachWrapper()
    peach.set_access_token(pkey, unique_id=unique_id, register=False)
    print(peach.get_self_user())
    print(peach.get_fee_estimates())
    print(peach.get_self_payment_method_info())
    print(peach.get_self_trading_limits())




    pass
if __name__ == '__main__':
    main()

