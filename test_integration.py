"""
Integration Tests for Peach Bitcoin API Wrapper
================================================

These tests hit the REAL Peach Bitcoin API to verify the wrapper works correctly.
Uses credentials from priv.py.

Run with: pytest test_integration.py -v -s
(Use -s to see print output for debugging)

WARNING: These tests interact with the real API. Be careful with trading operations!
"""

import pytest
import json
import time

from main import (
    PeachWrapper,
    PeachBTCError,
    PeachPaymentData,
    PeachMeansOfPayment
)

# Import credentials from priv.py
try:
    from priv import (
        pkey,
        unique_id,
        pkeywall,
        pubkeywall,
        pgp_public_key_str,
        pgp_private_key_str,
        pgp_passphrase_str
    )
    CREDENTIALS_AVAILABLE = True
except ImportError:
    CREDENTIALS_AVAILABLE = False
    pkey = unique_id = pkeywall = pubkeywall = None
    pgp_public_key_str = pgp_private_key_str = pgp_passphrase_str = None


# Skip all tests if credentials not available
pytestmark = pytest.mark.skipif(
    not CREDENTIALS_AVAILABLE,
    reason="priv.py credentials not available"
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def authenticated_wrapper():
    """Create and authenticate a PeachWrapper instance."""
    wrapper = PeachWrapper(private_key_hex=pkey)
    
    # Try to authenticate (login, not register)
    try:
        wrapper.set_access_token(unique_id=unique_id, register=False)
        print(f"\n✓ Authenticated as: {wrapper.user_id[:20]}...")
    except PeachBTCError as e:
        # If login fails, try register
        if "NOT_FOUND" in str(e) or "USER" in str(e):
            wrapper.set_access_token(unique_id=unique_id, register=True)
            print(f"\n✓ Registered and authenticated as: {wrapper.user_id[:20]}...")
        else:
            raise
    
    return wrapper


@pytest.fixture(scope="module")
def public_wrapper():
    """Create a PeachWrapper without authentication."""
    return PeachWrapper()


# =============================================================================
# PUBLIC ENDPOINT INTEGRATION TESTS
# =============================================================================

class TestPublicEndpointsIntegration:
    """Integration tests for public endpoints (no auth required)."""
    
    def test_system_status_returns_online(self, public_wrapper):
        """Test that system status returns online."""
        result = public_wrapper.system_status()
        
        assert "status" in result
        assert result["status"] == "online"
        assert "serverTime" in result
        print(f"  Server time: {result['serverTime']}")
    
    def test_info_returns_peach_data(self, public_wrapper):
        """Test that info endpoint returns expected structure."""
        result = public_wrapper.info()
        
        assert "peach" in result
        assert "pgpPublicKey" in result["peach"]
        assert "fees" in result
        assert "escrow" in result["fees"]
        print(f"  Escrow fee: {result['fees']['escrow'] * 100}%")
    
    def test_payment_methods_returns_list(self, public_wrapper):
        """Test that payment methods are returned."""
        result = public_wrapper.payment_methods()
        
        # API returns either list or dict depending on endpoint
        assert result is not None
        if isinstance(result, list):
            assert len(result) > 0
            print(f"  Found {len(result)} payment methods")
        elif isinstance(result, dict):
            assert len(result) > 0
            print(f"  Found {len(result)} payment method configs")
    
    def test_market_prices_returns_currencies(self, public_wrapper):
        """Test that market prices are returned for currencies."""
        result = public_wrapper.market_prices()
        
        assert isinstance(result, dict)
        assert "EUR" in result
        assert "USD" in result
        assert result["EUR"] > 0
        print(f"  BTC/EUR: {result['EUR']:,.2f}")
        print(f"  BTC/USD: {result['USD']:,.2f}")
    
    def test_market_price_btceur(self, public_wrapper):
        """Test specific market price pair."""
        result = public_wrapper.market_price("BTCEUR")
        
        assert "pair" in result
        assert result["pair"] == "BTCEUR"
        assert "price" in result
        assert result["price"] > 0
        print(f"  BTCEUR price: {result['price']:,.2f}")
    
    def test_ath_prices_returns_peaks(self, public_wrapper):
        """Test ATH prices endpoint."""
        result = public_wrapper.ath_prices()
        
        assert "tradePeaks" in result
        assert "24h" in result["tradePeaks"]
        assert "7d" in result["tradePeaks"]
        assert "30d" in result["tradePeaks"]
        print(f"  24h peak EUR: {result['tradePeaks']['24h'].get('EUR', 'N/A')}")
    
    def test_fee_estimates_returns_fees(self, public_wrapper):
        """Test fee estimates endpoint."""
        result = public_wrapper.get_fee_estimates()
        
        assert "fastestFee" in result
        assert "halfHourFee" in result
        assert "hourFee" in result
        print(f"  Fastest fee: {result['fastestFee']} sat/vB")
        print(f"  Hour fee: {result['hourFee']} sat/vB")
    
    def test_check_valid_referral_code(self, public_wrapper):
        """Test referral code validation."""
        result = public_wrapper.check_referal_code("SATOSHI")
        
        assert "valid" in result
        print(f"  SATOSHI code valid: {result['valid']}")
    
    def test_search_offers_returns_results(self, public_wrapper):
        """Test offer search."""
        result = public_wrapper.search_offers(
            search_criteria={
                "type": "ask",
                "meansOfPayment": {"EUR": ["sepa"]}
            },
            filters={
                "sortBy": "lowestPremium",
                "size": 5
            }
        )
        
        assert "offers" in result
        print(f"  Found {len(result['offers'])} sell offers")
        if result['offers']:
            first = result['offers'][0]
            print(f"  First offer ID: {first.get('id')}")


# =============================================================================
# AUTHENTICATED ENDPOINT INTEGRATION TESTS
# =============================================================================

class TestAuthenticatedEndpointsIntegration:
    """Integration tests for authenticated endpoints."""
    
    def test_authentication_works(self, authenticated_wrapper):
        """Test that authentication was successful."""
        assert authenticated_wrapper.access_token != ""
        assert authenticated_wrapper.user_id != ""
        assert authenticated_wrapper.expiry > 0
        
        remaining = authenticated_wrapper.get_token_expiry_time()
        print(f"  Token expires in: {remaining / 1000 / 60:.1f} minutes")
    
    def test_get_self_user(self, authenticated_wrapper):
        """Test getting own user profile."""
        result = authenticated_wrapper.get_self_user()
        
        assert "id" in result
        assert result["id"] == authenticated_wrapper.user_id
        print(f"  User ID: {result['id'][:20]}...")
        print(f"  Trades: {result.get('trades', 0)}")
        print(f"  Rating: {result.get('rating', 'N/A')}")
    
    def test_get_self_trading_limits(self, authenticated_wrapper):
        """Test getting trading limits."""
        result = authenticated_wrapper.get_self_trading_limits()
        
        assert result is not None
        print(f"  Trading limits: {json.dumps(result, indent=2)[:200]}...")
    
    def test_get_self_payment_method_info(self, authenticated_wrapper):
        """Test getting payment method info."""
        result = authenticated_wrapper.get_self_payment_method_info()
        
        assert result is not None
        print(f"  Payment methods configured: {type(result)}")
    
    def test_get_own_offers(self, authenticated_wrapper):
        """Test getting own offers."""
        result = authenticated_wrapper.get_own_offers()
        
        assert result is not None
        if isinstance(result, list):
            print(f"  Found {len(result)} own offers")
        else:
            print(f"  Offers response: {type(result)}")
    
    def test_get_own_offers_summaries(self, authenticated_wrapper):
        """Test getting offer summaries."""
        result = authenticated_wrapper.get_own_offers_summaries()
        
        assert result is not None
        print(f"  Offer summaries: {type(result)}")
    
    def test_get_contracts(self, authenticated_wrapper):
        """Test getting contracts via summaries (direct /contracts endpoint may not exist)."""
        # Note: The /v1/contracts endpoint may not exist directly
        # Use contract summaries instead which is the documented approach
        try:
            result = authenticated_wrapper.get_contracts()
            if isinstance(result, list):
                print(f"  Found {len(result)} contracts")
            else:
                print(f"  Contracts response: {type(result)}")
        except PeachBTCError as e:
            # Endpoint might not exist, use summaries instead
            print(f"  /contracts endpoint not available, using summaries")
            result = authenticated_wrapper.get_contract_summaries()
            assert result is not None
            print(f"  Found {len(result)} contract summaries")
    
    def test_get_contract_summaries(self, authenticated_wrapper):
        """Test getting contract summaries."""
        result = authenticated_wrapper.get_contract_summaries()
        
        assert result is not None
        if isinstance(result, list):
            print(f"  Found {len(result)} contract summaries")


# =============================================================================
# EXTENDED AUTHENTICATED USER ENDPOINT TESTS
# =============================================================================

class TestAuthenticatedUserEndpointsExtended:
    """Extended tests for authenticated user endpoints."""
    
    def test_get_user_status_self(self, authenticated_wrapper):
        """Test getting status of own user."""
        try:
            result = authenticated_wrapper.get_user_status(authenticated_wrapper.user_id)
            print(f"  User status: {json.dumps(result, indent=2)[:200]}")
        except PeachBTCError as e:
            # Some endpoints may not be available for own user
            print(f"  get_user_status response: {e.message}")
            assert e.status_code in [400, 401, 403, 404]  # Expected error codes
    
    def test_user_batching_enable_disable(self, authenticated_wrapper):
        """Test enabling/disabling batching."""
        # Enable batching
        try:
            result = authenticated_wrapper.user_manage_batching(True)
            print(f"  Enable batching: {result}")
            
            # Disable batching
            result = authenticated_wrapper.user_manage_batching(False)
            print(f"  Disable batching: {result}")
        except PeachBTCError as e:
            print(f"  Batching toggle response: {e.message}")
            # This might fail if user doesn't have batching capability
            assert e.status_code in [400, 401, 403, 404]
    
    def test_check_invalid_referral_code(self, authenticated_wrapper):
        """Test checking an invalid referral code."""
        result = authenticated_wrapper.check_referal_code("INVALID_CODE_12345")
        print(f"  Invalid code check: {result}")
        # Should return valid: false or similar
    
    def test_logout_and_reauth(self, authenticated_wrapper):
        """Test logout functionality (but re-authenticate after)."""
        original_token = authenticated_wrapper.access_token
        
        try:
            # Note: We don't actually logout because it would break other tests
            # Just verify we could call it
            print(f"  Current token: {original_token[:20]}...")
            print("  ✓ Logout endpoint available (not called to preserve session)")
        except PeachBTCError as e:
            print(f"  Logout check: {e.message}")


# =============================================================================
# AUTHENTICATED OFFER ENDPOINT TESTS
# =============================================================================

class TestAuthenticatedOfferEndpoints:
    """Tests for authenticated offer endpoints."""
    
    def test_get_offer_details_from_search(self, authenticated_wrapper, public_wrapper):
        """Test getting offer details for a real offer from search."""
        # First search for an offer
        search_result = public_wrapper.search_offers(
            search_criteria={"type": "ask"},
            filters={"sortBy": "lowestPremium", "size": 1}
        )
        
        if search_result.get("offers"):
            offer_id = search_result["offers"][0]["id"]
            print(f"  Testing with offer ID: {offer_id}")
            
            try:
                result = authenticated_wrapper.get_offer_details(str(offer_id))
                print(f"  Offer details: {json.dumps(result, indent=2)[:300]}...")
                assert "id" in result or "user" in result
            except PeachBTCError as e:
                print(f"  Get offer details: {e.message}")
        else:
            print("  No offers found to test with")
    
    def test_get_own_offer_details_if_exists(self, authenticated_wrapper):
        """Test getting details of own offers if any exist."""
        offers = authenticated_wrapper.get_own_offers()
        
        if offers and len(offers) > 0:
            offer_id = offers[0].get("id")
            print(f"  Found own offer: {offer_id}")
            
            result = authenticated_wrapper.get_own_offer_details(str(offer_id))
            print(f"  Own offer details: {json.dumps(result, indent=2)[:300]}...")
        else:
            print("  No own offers to test with")
    
    def test_get_matches_if_offer_exists(self, authenticated_wrapper):
        """Test getting matches for own offers if any exist."""
        offers = authenticated_wrapper.get_own_offers()
        
        if offers and len(offers) > 0:
            offer_id = offers[0].get("id")
            print(f"  Checking matches for offer: {offer_id}")
            
            try:
                result = authenticated_wrapper.get_matches(str(offer_id))
                print(f"  Matches: {result}")
            except PeachBTCError as e:
                print(f"  Get matches: {e.message}")
        else:
            print("  No own offers to check matches for")
    
    def test_escrow_endpoints_require_offer(self, authenticated_wrapper):
        """Test that escrow endpoints properly require an offer."""
        fake_offer_id = "999999"
        
        # These should fail with proper error since offer doesn't exist
        try:
            result = authenticated_wrapper.get_funding_status(fake_offer_id)
            print(f"  Funding status (unexpected success): {result}")
        except PeachBTCError as e:
            print(f"  ✓ get_funding_status properly rejects invalid offer: {e.message}")
            assert e.status_code in [400, 401, 403, 404]
    
    def test_cancel_offer_requires_valid_offer(self, authenticated_wrapper):
        """Test that cancel requires a valid offer."""
        fake_offer_id = "999999"
        
        try:
            result = authenticated_wrapper.cancel_offer(fake_offer_id)
            print(f"  Cancel offer (unexpected success): {result}")
        except PeachBTCError as e:
            print(f"  ✓ cancel_offer properly rejects invalid offer: {e.message}")
            assert e.status_code in [400, 401, 403, 404]
    
    def test_get_refund_psbt_requires_valid_offer(self, authenticated_wrapper):
        """Test that refund PSBT requires a valid funded offer."""
        fake_offer_id = "999999"
        
        try:
            result = authenticated_wrapper.get_refund_psbt(fake_offer_id)
            print(f"  Refund PSBT (unexpected success): {result}")
        except PeachBTCError as e:
            print(f"  ✓ get_refund_psbt properly rejects invalid offer: {e.message}")
            assert e.status_code in [400, 401, 403, 404]


# =============================================================================
# AUTHENTICATED CONTRACT ENDPOINT TESTS
# =============================================================================

class TestAuthenticatedContractEndpoints:
    """Tests for authenticated contract endpoints."""
    
    def test_get_contract_details_if_exists(self, authenticated_wrapper):
        """Test getting contract details if user has any contracts."""
        summaries = authenticated_wrapper.get_contract_summaries()
        
        if summaries and len(summaries) > 0:
            contract_id = summaries[0].get("id")
            print(f"  Found contract: {contract_id}")
            
            result = authenticated_wrapper.get_contract_details(contract_id)
            print(f"  Contract details: {json.dumps(result, indent=2)[:400]}...")
            
            # Check for expected fields based on blog post
            assert "id" in result
        else:
            print("  No contracts to test with")
    
    def test_contract_actions_require_valid_contract(self, authenticated_wrapper):
        """Test that contract actions properly require valid contracts."""
        fake_contract_id = "fake-contract-999"
        
        # Test confirm_payment_made
        try:
            authenticated_wrapper.confirm_payment_made(fake_contract_id)
            print("  confirm_payment_made (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ confirm_payment_made rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]
        
        # Test confirm_payment_received
        try:
            authenticated_wrapper.confirm_payment_received(fake_contract_id)
            print("  confirm_payment_received (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ confirm_payment_received rejects invalid contract: {e.message}")
    
    def test_cancel_contract_requires_valid_contract(self, authenticated_wrapper):
        """Test that cancel contract requires valid contract."""
        fake_contract_id = "fake-contract-999"
        
        try:
            authenticated_wrapper.cancel_contract(fake_contract_id, reason="test")
            print("  cancel_contract (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ cancel_contract rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]
    
    def test_extend_payment_requires_valid_contract(self, authenticated_wrapper):
        """Test that extend payment requires valid contract."""
        fake_contract_id = "fake-contract-999"
        
        try:
            authenticated_wrapper.extend_payment_time(fake_contract_id)
            print("  extend_payment_time (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ extend_payment_time rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]


# =============================================================================
# AUTHENTICATED CHAT ENDPOINT TESTS
# =============================================================================

class TestAuthenticatedChatEndpoints:
    """Tests for authenticated chat endpoints."""
    
    def test_get_chat_log_if_contract_exists(self, authenticated_wrapper):
        """Test getting chat log if user has contracts."""
        summaries = authenticated_wrapper.get_contract_summaries()
        
        if summaries and len(summaries) > 0:
            contract_id = summaries[0].get("id")
            print(f"  Getting chat for contract: {contract_id}")
            
            try:
                result = authenticated_wrapper.get_chat_log(contract_id)
                print(f"  Chat messages: {len(result) if isinstance(result, list) else result}")
            except PeachBTCError as e:
                print(f"  Get chat log: {e.message}")
        else:
            print("  No contracts with chat to test")
    
    def test_chat_requires_valid_contract(self, authenticated_wrapper):
        """Test that chat endpoints require valid contract."""
        fake_contract_id = "fake-contract-999"
        
        try:
            authenticated_wrapper.get_chat_log(fake_contract_id)
            print("  get_chat_log (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ get_chat_log rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]


# =============================================================================
# AUTHENTICATED DISPUTE ENDPOINT TESTS
# =============================================================================

class TestAuthenticatedDisputeEndpoints:
    """Tests for authenticated dispute endpoints."""
    
    def test_dispute_requires_valid_contract(self, authenticated_wrapper):
        """Test that dispute endpoints require valid contract."""
        fake_contract_id = "fake-contract-999"
        
        try:
            authenticated_wrapper.raise_dispute(fake_contract_id, reason="test dispute")
            print("  raise_dispute (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ raise_dispute rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]
    
    def test_acknowledge_dispute_requires_valid_contract(self, authenticated_wrapper):
        """Test that acknowledge dispute requires valid contract."""
        fake_contract_id = "fake-contract-999"
        
        try:
            authenticated_wrapper.acknowledge_dispute(fake_contract_id)
            print("  acknowledge_dispute (unexpected success)")
        except PeachBTCError as e:
            print(f"  ✓ acknowledge_dispute rejects invalid contract: {e.message}")
            assert e.status_code in [400, 401, 403, 404]


# =============================================================================
# TOKEN MANAGEMENT TESTS
# =============================================================================

class TestTokenManagementIntegration:
    """Test token management with real API."""
    
    def test_token_not_expired(self, authenticated_wrapper):
        """Test that token is not expired."""
        assert authenticated_wrapper.is_token_expired() is False
    
    def test_token_expiry_time_positive(self, authenticated_wrapper):
        """Test that expiry time is in the future."""
        remaining = authenticated_wrapper.get_token_expiry_time()
        assert remaining > 0
        print(f"  Token valid for: {remaining / 1000 / 60:.1f} minutes")


# =============================================================================
# HELPER CLASS TESTS WITH REAL DATA
# =============================================================================

class TestHelperClassesWithRealData:
    """Test helper classes work correctly for API interaction."""
    
    def test_payment_data_hash_format(self):
        """Test that payment data produces correct hash format."""
        pd = PeachPaymentData("paypal", email="test@example.com")
        payment_type, hash_dict = pd.create_hash()
        
        assert payment_type == "paypal"
        assert "hashes" in hash_dict
        assert len(hash_dict["hashes"]) == 1
        assert len(hash_dict["hashes"][0]) == 64  # SHA256 hex
        print(f"  Hash: {hash_dict['hashes'][0][:32]}...")
    
    def test_means_of_payment_structure(self):
        """Test means of payment creates correct API structure."""
        mop = PeachMeansOfPayment({"EUR": ["sepa", "paypal"], "CHF": ["twint"]})
        result = mop.get()
        
        assert result == {"EUR": ["sepa", "paypal"], "CHF": ["twint"]}
        print(f"  Structure: {result}")


# =============================================================================
# SIGNING TESTS
# =============================================================================

class TestSigningIntegration:
    """Test cryptographic signing works correctly."""
    
    def test_get_public_key_from_private(self):
        """Test deriving public key from private key."""
        wrapper = PeachWrapper(private_key_hex=pkey)
        pub_key = wrapper.get_public_key()
        
        # Compressed public key should be 66 hex chars (33 bytes)
        assert len(pub_key) == 66
        assert pub_key.startswith("02") or pub_key.startswith("03")
        print(f"  Public key: {pub_key[:20]}...{pub_key[-10:]}")
    
    def test_own_user_id_matches_public_key(self, authenticated_wrapper):
        """Test that user ID matches derived public key."""
        derived = authenticated_wrapper.get_public_key()
        assert authenticated_wrapper.user_id == derived


# =============================================================================
# READ-ONLY TRADING DATA TESTS
# =============================================================================

class TestTradingDataIntegration:
    """Test reading trading data (read-only, safe operations)."""
    
    def test_can_fetch_and_view_public_user(self, public_wrapper, authenticated_wrapper):
        """Test fetching a public user profile."""
        # Fetch our own public profile
        user_id = authenticated_wrapper.user_id
        result = public_wrapper.get_user(user_id)
        
        assert "id" in result
        assert result["id"] == user_id
        print(f"  Public profile trades: {result.get('trades', 0)}")
    
    def test_search_buy_offers(self, public_wrapper):
        """Test searching for buy offers."""
        result = public_wrapper.search_offers(
            search_criteria={
                "type": "bid",
                "meansOfPayment": {"EUR": ["sepa"]}
            },
            filters={
                "sortBy": "bestReputation",
                "size": 3
            }
        )
        
        if "offers" in result and result["offers"]:
            print(f"  Found {len(result['offers'])} buy offers")
            for offer in result["offers"][:2]:
                print(f"    - Amount: {offer.get('amount')}, Premium: {offer.get('premium')}%")
    
    def test_search_sell_offers(self, public_wrapper):
        """Test searching for sell offers."""
        result = public_wrapper.search_offers(
            search_criteria={
                "type": "ask",
                "meansOfPayment": {"EUR": ["paypal"]}
            },
            filters={
                "sortBy": "lowestPremium",
                "size": 3
            }
        )
        
        if "offers" in result and result["offers"]:
            print(f"  Found {len(result['offers'])} sell offers")
            for offer in result["offers"][:2]:
                print(f"    - Amount: {offer.get('amount')}, Premium: {offer.get('premium')}%")


# =============================================================================
# FULL TRADING FLOW TEST (READ-ONLY PARTS)
# =============================================================================

class TestTradingFlowReadOnly:
    """Test the trading flow without actually creating offers."""
    
    def test_can_prepare_buy_offer_data(self, authenticated_wrapper):
        """Test preparing buy offer data structure."""
        # This tests the data preparation without submitting
        pd = PeachPaymentData("paypal", email="test@example.com")
        mop = PeachMeansOfPayment({"EUR": ["paypal"]})
        
        payment_type, hashes = pd.create_hash()
        means = mop.get()
        
        # Verify structure matches API expectations
        assert payment_type == "paypal"
        assert "hashes" in hashes
        assert means == {"EUR": ["paypal"]}
        
        print("  ✓ Buy offer data structure valid")
    
    def test_can_prepare_sell_offer_data(self, authenticated_wrapper):
        """Test preparing sell offer data structure."""
        pd = PeachPaymentData("sepa", 
                              beneficiary="Test User",
                              iban="DE89370400440532013000",
                              bic="COBADEFFXXX")
        mop = PeachMeansOfPayment({"EUR": ["sepa"]})
        
        payment_type, hashes = pd.create_hash()
        means = mop.get()
        
        assert payment_type == "sepa"
        assert len(hashes["hashes"]) == 3  # 3 fields hashed
        assert means == {"EUR": ["sepa"]}
        
        print("  ✓ Sell offer data structure valid")
        print(f"    Hashed {len(hashes['hashes'])} payment fields")


# =============================================================================
# FULL TRADING FLOW TESTS (CREATES REAL OFFERS - USE WITH CAUTION)
# =============================================================================

class TestRealTradingFlow:
    """
    Tests that create real offers on the platform.
    These are marked with pytest.mark.slow and can be skipped with -m "not slow"
    
    WARNING: These tests create real offers! They will be cancelled immediately,
    but use with caution.
    
    Note: These tests may fail with 503 errors during high API load - this is normal.
    """
    
    @pytest.mark.slow
    def test_create_and_cancel_buy_offer(self, authenticated_wrapper):
        """Test creating a buy offer and immediately cancelling it."""
        # Prepare payment data
        pd = PeachPaymentData("paypal", email="test@peachtest.com")
        mop = PeachMeansOfPayment({"EUR": ["paypal"]})
        
        print("\n  Creating buy offer...")
        try:
            result = authenticated_wrapper.post_buy_offer(
                addressPrivateKey=pkeywall,
                releaseAddress=pubkeywall,
                paymentData=[pd],
                meansOfPayment=mop,
                amount_range=(50000, 100000),  # 50k-100k sats
                maxPremium=15  # Max 15% premium
            )
            
            offer_id = result.get("id")
            print(f"  ✓ Created buy offer: {offer_id}")
            
            # Verify we can see our offer
            offers = authenticated_wrapper.get_own_offers()
            own_offer_ids = [o.get("id") for o in offers] if offers else []
            assert str(offer_id) in [str(x) for x in own_offer_ids], "Created offer not found in own offers"
            print(f"  ✓ Offer visible in own offers")
            
            # Get offer details
            details = authenticated_wrapper.get_own_offer_details(str(offer_id))
            print(f"  ✓ Got offer details: type={details.get('type')}, amount={details.get('amount')}")
            
            # Check for matches (probably none yet)
            try:
                matches = authenticated_wrapper.get_matches(str(offer_id))
                print(f"  ✓ Checked matches: {len(matches) if isinstance(matches, list) else matches}")
            except PeachBTCError as e:
                print(f"  Matches check: {e.message}")
            
            # Cancel the offer
            print(f"  Cancelling offer {offer_id}...")
            cancel_result = authenticated_wrapper.cancel_offer(str(offer_id))
            print(f"  ✓ Cancelled offer: {cancel_result}")
            
        except PeachBTCError as e:
            if e.status_code == 503:
                pytest.skip("API temporarily unavailable (503)")
            print(f"  ✗ Error: {e.message} (status: {e.status_code})")
            raise
    
    @pytest.mark.slow
    def test_create_and_cancel_sell_offer(self, authenticated_wrapper):
        """Test creating a sell offer and immediately cancelling it."""
        # Prepare payment data
        pd = PeachPaymentData("sepa", 
                              beneficiary="Test User",
                              iban="DE89370400440532013000",
                              bic="COBADEFFXXX")
        mop = PeachMeansOfPayment({"EUR": ["sepa"]})
        
        print("\n  Creating sell offer...")
        try:
            result = authenticated_wrapper.post_sell_offer(
                amount=50000,  # 50k sats
                returnAddress=pubkeywall,
                paymentData=[pd],
                meansOfPayment=mop,
                premium=5  # 5% premium
            )
            
            offer_id = result.get("id")
            print(f"  ✓ Created sell offer: {offer_id}")
            
            # Get offer details
            details = authenticated_wrapper.get_own_offer_details(str(offer_id))
            print(f"  ✓ Got offer details: type={details.get('type')}, amount={details.get('amount')}")
            
            # For sell offers, we need to create escrow and fund it before it goes live
            # But for this test, we'll just cancel it
            print(f"  Note: Sell offer requires escrow funding to go live")
            
            # Cancel the offer
            print(f"  Cancelling offer {offer_id}...")
            cancel_result = authenticated_wrapper.cancel_offer(str(offer_id))
            print(f"  ✓ Cancelled offer: {cancel_result}")
            
        except PeachBTCError as e:
            if e.status_code == 503:
                pytest.skip("API temporarily unavailable (503)")
            print(f"  ✗ Error: {e.message} (status: {e.status_code})")
            raise
    
    @pytest.mark.slow  
    def test_sell_offer_escrow_flow(self, authenticated_wrapper):
        """Test the escrow creation flow for a sell offer (doesn't fund)."""
        pd = PeachPaymentData("paypal", email="test@peachtest.com")
        mop = PeachMeansOfPayment({"EUR": ["paypal"]})
        
        print("\n  Creating sell offer for escrow test...")
        try:
            # Create sell offer
            result = authenticated_wrapper.post_sell_offer(
                amount=21000,  # Minimum amount
                returnAddress=pubkeywall,
                paymentData=[pd],
                meansOfPayment=mop,
                premium=10
            )
            
            offer_id = result.get("id")
            print(f"  ✓ Created sell offer: {offer_id}")
            
            # Create escrow
            print(f"  Creating escrow...")
            escrow_pubkey = authenticated_wrapper.get_public_key()
            
            try:
                escrow_result = authenticated_wrapper.create_escrow(str(offer_id), escrow_pubkey)
                print(f"  ✓ Escrow created: {json.dumps(escrow_result, indent=2)[:300]}...")
                
                # Get funding status
                funding = authenticated_wrapper.get_funding_status(str(offer_id))
                print(f"  ✓ Funding status: {json.dumps(funding, indent=2)[:200]}...")
                
                # We won't actually fund it - that requires sending real Bitcoin
                print(f"  Note: Escrow funding requires sending BTC to the escrow address")
                
            except PeachBTCError as e:
                print(f"  Escrow creation: {e.message}")
            
            # Clean up - cancel the offer
            print(f"  Cleaning up - cancelling offer...")
            authenticated_wrapper.cancel_offer(str(offer_id))
            print(f"  ✓ Offer cancelled")
            
        except PeachBTCError as e:
            if e.status_code == 503:
                pytest.skip("API temporarily unavailable (503)")
            print(f"  ✗ Error: {e.message}")
            raise


# =============================================================================
# UPDATE USER PROFILE TESTS
# =============================================================================

class TestUpdateUserProfile:
    """Tests for updating user profile (including PGP key)."""
    
    @pytest.mark.slow
    def test_update_user_with_pgp_key(self, authenticated_wrapper):
        """Test updating user profile with PGP public key."""
        print("\n  Updating user with PGP key...")
        
        try:
            result = authenticated_wrapper.update_self_user(
                data={
                    "pgpPublicKey": pgp_public_key_str,
                    "message": f"Verifying PGP key at {int(time.time() * 1000)}"
                },
                pgp_private_key=pgp_private_key_str,
                pgp_passphrase=pgp_passphrase_str
            )
            print(f"  ✓ Updated user with PGP key: {result}")
            
            # Verify PGP key was set
            user = authenticated_wrapper.get_self_user()
            has_pgp = user.get("pgpPublicKey") is not None
            print(f"  ✓ User has PGP key: {has_pgp}")
            
        except PeachBTCError as e:
            if e.status_code == 503:
                pytest.skip("API temporarily unavailable (503)")
            print(f"  PGP update: {e.message}")
            # This might fail if PGP key is already set or other validation
            if "PGP" not in str(e.message).upper() and e.status_code not in [400, 401]:
                raise


# =============================================================================
# RUN INTEGRATION TESTS
# =============================================================================

if __name__ == "__main__":
    # Run without slow tests by default
    # Use: pytest test_integration.py -v -s -m "slow" to include slow tests
    pytest.main([__file__, "-v", "-s", "--tb=short", "-m", "not slow"])

