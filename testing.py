from main import PeachWrapper


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





