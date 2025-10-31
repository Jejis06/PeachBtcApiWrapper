import requests as rq

# TODO: gl for erroro check
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

        self.session: rq.Session = rq.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'PeachBitcoin-Python-Wrapper/1.0'
        })

        # set access token (encrypted private key)
        if self.access_token != '':
            self.session.headers.update({
                'Authorization': f'Bearer {self.access_token}'
            })

        pass

    def __send_request(self, method: str, suburl: str) -> dict[str, int | float | str]:

        if method.upper() not in ['GET', 'POST']:
            raise ValueError(f"Unsupported HTTP method: {method}")

        resp = self.session.request(method, f"{self.base_url}/{self.version}/{suburl}")

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

    # Market endpoints 
    def market_price(self, pair: str):
        resp = self.__send_request('GET', f'market/price/{pair}')
        return resp

    def market_prices(self):
        resp = self.__send_request('GET', 'market/prices')
        return resp

    def ath_prices(self):
        resp = self.__send_request('GET','market/tradePricePeaks')
        return resp

    # User endpoints
    def get_user(self, userid: str):
        # userid = public key
        resp = self.__send_request('GET', f'user/{userid}')
        return resp

    def get_user_rating(self, userid: str):
        resp = self.__send_request('GET', f'user/{userid}/ratings')
        return resp

    def check_referal_code(self, code: str):
        resp = self.__send_request('GET', f'user/referral?code={code}')
        return resp

    # Offer endpoint
    def get_offer_details(self, offerid: str):
        resp = self.__send_request('GET', f'offer/{offerid}')
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
    user = ("03870fb8d201672926c247e9f98ba43620db1695ed57e9c098f9988a58485a2565")
    print("GET USER ---- ")
    print(peach.get_user(user))

    print("GET USER RATING---- ")
    print(peach.get_user_rating(user))

    print("CHECK REFERAL CODE---- ")
    print(peach.check_referal_code("SATOSHI"))


def main():
    peach: PeachWrapper = PeachWrapper()


    pass
if __name__ == '__main__':
    main()
