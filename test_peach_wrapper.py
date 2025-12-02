"""
Comprehensive Unit Tests for Peach Bitcoin API Wrapper
======================================================

This test suite covers all methods in the PeachWrapper class using mocking
to avoid hitting the real API. Tests are organized by endpoint category.

Run tests with: pytest test_peach_wrapper.py -v
Run with coverage: pytest test_peach_wrapper.py -v --cov=main --cov-report=term-missing
"""

import pytest
import hashlib
import time
from unittest.mock import Mock, patch, MagicMock
import json

# Import the wrapper components
from main import (
    PeachWrapper,
    PeachBTCError,
    PeachPaymentData,
    PeachMeansOfPayment
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_private_key():
    """A valid 64-character hex private key for testing."""
    return "0" * 64  # Simplified for testing


@pytest.fixture
def mock_public_key():
    """Expected public key corresponding to mock_private_key."""
    return "02" + "0" * 64  # Simplified mock


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    with patch('main.rq.Session') as mock:
        yield mock


@pytest.fixture
def wrapper():
    """Create a PeachWrapper instance without auth."""
    return PeachWrapper()


@pytest.fixture
def authenticated_wrapper(mock_private_key):
    """Create a PeachWrapper instance with mocked authentication."""
    with patch.object(PeachWrapper, '_PeachWrapper__send_request') as mock_request:
        mock_request.return_value = {
            'accessToken': 'test-token-12345',
            'expiry': int(time.time() * 1000) + 3600000  # 1 hour from now
        }
        wrapper = PeachWrapper(private_key_hex=mock_private_key)
        wrapper.set_access_token(register=False)
        return wrapper


# =============================================================================
# HELPER CLASS TESTS
# =============================================================================

class TestPeachBTCError:
    """Tests for PeachBTCError exception class."""
    
    def test_error_creation_with_defaults(self):
        """Test error creation with default values."""
        error = PeachBTCError("Test error")
        assert error.message == "Test error"
        assert error.status_code == 999
        assert error.error_id == ""
    
    def test_error_creation_with_all_params(self):
        """Test error creation with all parameters."""
        error = PeachBTCError("Bad request", 400, "BAD_REQUEST")
        assert error.message == "Bad request"
        assert error.status_code == 400
        assert error.error_id == "BAD_REQUEST"
    
    def test_error_repr(self):
        """Test error string representation."""
        error = PeachBTCError("Test", 400, "TEST_ID")
        repr_str = repr(error)
        assert "PeachBTCError" in repr_str
        assert "Test" in repr_str
        assert "400" in repr_str
        assert "TEST_ID" in repr_str
    
    def test_error_is_exception(self):
        """Test that PeachBTCError is a proper exception."""
        with pytest.raises(PeachBTCError) as excinfo:
            raise PeachBTCError("Test error", 500)
        assert excinfo.value.status_code == 500


class TestPeachPaymentData:
    """Tests for PeachPaymentData class."""
    
    def test_creation_single_field(self):
        """Test creation with a single payment field."""
        pd = PeachPaymentData("paypal", email="test@example.com")
        assert pd.payment_type == "paypal"
        assert pd.payment_fields == {"email": "test@example.com"}
    
    def test_creation_multiple_fields(self):
        """Test creation with multiple payment fields."""
        pd = PeachPaymentData("sepa", iban="DE89370400440532013000", bic="COBADEFFXXX")
        assert pd.payment_type == "sepa"
        assert "iban" in pd.payment_fields
        assert "bic" in pd.payment_fields
    
    def test_create_hash_single_field(self):
        """Test hash creation for single field."""
        pd = PeachPaymentData("paypal", email="test@example.com")
        payment_type, hash_dict = pd.create_hash()
        
        assert payment_type == "paypal"
        assert "hashes" in hash_dict
        assert len(hash_dict["hashes"]) == 1
        
        # Verify hash is correct
        expected_hash = hashlib.sha256("test@example.com".encode()).hexdigest()
        assert hash_dict["hashes"][0] == expected_hash
    
    def test_create_hash_multiple_fields(self):
        """Test hash creation for multiple fields."""
        pd = PeachPaymentData("revolut", email="test@example.com", phone="+1234567890")
        payment_type, hash_dict = pd.create_hash()
        
        assert payment_type == "revolut"
        assert len(hash_dict["hashes"]) == 2
    
    def test_repr(self):
        """Test string representation."""
        pd = PeachPaymentData("paypal", email="test@example.com")
        repr_str = repr(pd)
        assert "PeachPaymentData" in repr_str
        assert "paypal" in repr_str
        assert "email" in repr_str


class TestPeachMeansOfPayment:
    """Tests for PeachMeansOfPayment class."""
    
    def test_creation(self):
        """Test basic creation."""
        mop = PeachMeansOfPayment({"EUR": ["sepa", "paypal"]})
        assert mop.get() == {"EUR": ["sepa", "paypal"]}
    
    def test_add_new_currency(self):
        """Test adding a new currency."""
        mop = PeachMeansOfPayment({"EUR": ["sepa"]})
        mop.add_new_type("CHF", ["twint"])
        
        result = mop.get()
        assert "EUR" in result
        assert "CHF" in result
        assert result["CHF"] == ["twint"]
    
    def test_extend_existing_currency(self):
        """Test extending payment methods for existing currency."""
        mop = PeachMeansOfPayment({"EUR": ["sepa"]})
        mop.add_new_type("EUR", ["paypal"])
        
        result = mop.get()
        assert "sepa" in result["EUR"]
        assert "paypal" in result["EUR"]
    
    def test_extend_no_duplicates(self):
        """Test that extending doesn't create duplicates."""
        mop = PeachMeansOfPayment({"EUR": ["sepa", "paypal"]})
        mop.add_new_type("EUR", ["sepa", "revolut"])
        
        result = mop.get()
        # Should have sepa, paypal, revolut without duplicates
        assert len(result["EUR"]) == 3
    
    def test_repr(self):
        """Test string representation."""
        mop = PeachMeansOfPayment({"EUR": ["sepa"]})
        repr_str = repr(mop)
        assert "PeachMeansOfPayment" in repr_str
        assert "EUR" in repr_str


# =============================================================================
# PEACH WRAPPER - INITIALIZATION TESTS
# =============================================================================

class TestPeachWrapperInit:
    """Tests for PeachWrapper initialization."""
    
    def test_default_initialization(self):
        """Test wrapper creation with default values."""
        wrapper = PeachWrapper()
        assert wrapper.base_url == "https://api.peachbitcoin.com"
        assert wrapper.version == "v1"
        assert wrapper.access_token == ""
        assert wrapper.private_key_hex == ""
        assert wrapper.expiry == -1
    
    def test_initialization_with_access_token(self):
        """Test wrapper creation with access token."""
        wrapper = PeachWrapper(access_token="test-token")
        assert wrapper.access_token == "test-token"
    
    def test_initialization_with_private_key(self, mock_private_key):
        """Test wrapper creation with private key."""
        wrapper = PeachWrapper(private_key_hex=mock_private_key)
        assert wrapper.private_key_hex == mock_private_key


# =============================================================================
# PEACH WRAPPER - TOKEN MANAGEMENT TESTS
# =============================================================================

class TestTokenManagement:
    """Tests for token expiry and refresh functionality."""
    
    def test_is_token_expired_no_expiry(self):
        """Test expired check when no expiry set."""
        wrapper = PeachWrapper()
        assert wrapper.is_token_expired() is True
    
    def test_is_token_expired_future(self):
        """Test expired check with future expiry."""
        wrapper = PeachWrapper()
        wrapper.expiry = int(time.time() * 1000) + 3600000  # 1 hour ahead
        assert wrapper.is_token_expired() is False
    
    def test_is_token_expired_past(self):
        """Test expired check with past expiry."""
        wrapper = PeachWrapper()
        wrapper.expiry = int(time.time() * 1000) - 1000  # 1 second ago
        assert wrapper.is_token_expired() is True
    
    def test_get_token_expiry_time_no_expiry(self):
        """Test expiry time when no expiry set."""
        wrapper = PeachWrapper()
        assert wrapper.get_token_expiry_time() == 0
    
    def test_get_token_expiry_time_valid(self):
        """Test expiry time with valid expiry."""
        wrapper = PeachWrapper()
        future_time = int(time.time() * 1000) + 60000  # 1 minute ahead
        wrapper.expiry = future_time
        remaining = wrapper.get_token_expiry_time()
        assert 0 < remaining <= 60000
    
    def test_refresh_token_raises_without_key(self):
        """Test that refresh raises error without private key."""
        wrapper = PeachWrapper()
        wrapper.expiry = int(time.time() * 1000) - 1000  # Expired
        with pytest.raises(PeachBTCError) as excinfo:
            wrapper.refresh_token_if_expired()
        assert "no private key" in str(excinfo.value.message).lower()


# =============================================================================
# PEACH WRAPPER - PUBLIC ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestPublicEndpoints:
    """Tests for public API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_system_status(self, mock_request):
        """Test system status endpoint."""
        mock_request.return_value = {
            "error": None,
            "status": "online",
            "serverTime": 1692788403879
        }
        
        wrapper = PeachWrapper()
        result = wrapper.system_status()
        
        mock_request.assert_called_once_with('GET', 'system/status')
        assert result["status"] == "online"
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_info(self, mock_request):
        """Test info endpoint."""
        mock_request.return_value = {
            "peach": {"pgpPublicKey": "-----BEGIN PGP..."},
            "fees": {"escrow": 0.02}
        }
        
        wrapper = PeachWrapper()
        result = wrapper.info()
        
        mock_request.assert_called_once_with('GET', 'info')
        assert "peach" in result
        assert result["fees"]["escrow"] == 0.02
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_payment_methods(self, mock_request):
        """Test payment methods endpoint."""
        mock_request.return_value = {
            "paypal": {"mandatory": [[["userName"], ["email"]]]},
            "sepa": {"mandatory": [[["beneficiary"]], [["iban"]]]}
        }
        
        wrapper = PeachWrapper()
        result = wrapper.payment_methods()
        
        mock_request.assert_called_once_with('GET', 'info/paymentMethods')
        assert "paypal" in result or isinstance(result, list)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_market_price(self, mock_request):
        """Test market price for specific pair."""
        mock_request.return_value = {
            "pair": "BTCEUR",
            "price": 27455.04,
            "date": "2023-04-18T15:28:35.525Z"
        }
        
        wrapper = PeachWrapper()
        result = wrapper.market_price("BTCEUR")
        
        mock_request.assert_called_once_with('GET', 'market/price/BTCEUR')
        assert result["pair"] == "BTCEUR"
        assert result["price"] == 27455.04
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_market_prices(self, mock_request):
        """Test all market prices."""
        mock_request.return_value = {
            "EUR": 27498.77,
            "CHF": 27191.85,
            "GBP": 24226.61
        }
        
        wrapper = PeachWrapper()
        result = wrapper.market_prices()
        
        mock_request.assert_called_once_with('GET', 'market/prices')
        assert "EUR" in result
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_ath_prices(self, mock_request):
        """Test ATH prices endpoint."""
        mock_request.return_value = {
            "tradePeaks": {
                "24h": {"EUR": 116926},
                "7d": {"EUR": 120565}
            }
        }
        
        wrapper = PeachWrapper()
        result = wrapper.ath_prices()
        
        mock_request.assert_called_once_with('GET', 'market/tradePricePeaks')
        assert "tradePeaks" in result
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_user(self, mock_request):
        """Test get public user info."""
        user_id = "02abc123"
        mock_request.return_value = {
            "id": user_id,
            "trades": 100,
            "rating": 0.95
        }
        
        wrapper = PeachWrapper()
        result = wrapper.get_user(user_id)
        
        mock_request.assert_called_once_with('GET', f'user/{user_id}')
        assert result["id"] == user_id
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_user_rating(self, mock_request):
        """Test get user ratings."""
        user_id = "02abc123"
        mock_request.return_value = [
            {"rating": 1, "creationDate": "2023-03-01"}
        ]
        
        wrapper = PeachWrapper()
        result = wrapper.get_user_rating(user_id)
        
        mock_request.assert_called_once_with('GET', f'user/{user_id}/ratings')
        assert isinstance(result, list)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_check_referral_code(self, mock_request):
        """Test referral code check."""
        mock_request.return_value = {"valid": True}
        
        wrapper = PeachWrapper()
        result = wrapper.check_referal_code("SATOSHI")
        
        mock_request.assert_called_once_with('GET', 'user/referral', params={"code": "SATOSHI"})
        assert result["valid"] is True
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_search_offers(self, mock_request):
        """Test offer search."""
        mock_request.return_value = {
            "offers": [{"id": "123", "type": "ask"}]
        }
        
        wrapper = PeachWrapper()
        criteria = {"type": "ask", "meansOfPayment": {"EUR": ["sepa"]}}
        filters = {"sortBy": "lowestPremium"}
        result = wrapper.search_offers(criteria, filters)
        
        mock_request.assert_called_once_with('POST', 'offer/search', data=criteria, params=filters)
        assert "offers" in result
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_fee_estimates(self, mock_request):
        """Test fee estimates endpoint."""
        mock_request.return_value = {
            "fastestFee": 10,
            "halfHourFee": 5,
            "hourFee": 3
        }
        
        wrapper = PeachWrapper()
        result = wrapper.get_fee_estimates()
        
        mock_request.assert_called_once_with('GET', 'estimateFees')
        assert "fastestFee" in result
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_transaction_data(self, mock_request):
        """Test get transaction data."""
        txid = "abc123def456"
        mock_request.return_value = {"txid": txid, "confirmations": 6}
        
        wrapper = PeachWrapper()
        result = wrapper.get_transaction_data(txid)
        
        mock_request.assert_called_once_with('GET', f'tx/{txid}')
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_post_transaction(self, mock_request):
        """Test post transaction."""
        tx_hex = "0100000001..."
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper()
        result = wrapper.post_transaction(tx_hex)
        
        mock_request.assert_called_once_with('POST', 'tx', data={'tx': tx_hex})
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_send_report(self, mock_request):
        """Test contact report."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper()
        result = wrapper.send_report(
            email="test@example.com",
            topic="bug",
            reason="Bug report",
            message="Found a bug"
        )
        
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[0][0] == 'POST'
        assert call_args[0][1] == 'contact/report'


# =============================================================================
# PEACH WRAPPER - PRIVATE USER ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestPrivateUserEndpoints:
    """Tests for private user API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_self_user(self, mock_request):
        """Test get self user endpoint."""
        mock_request.return_value = {
            "id": "02abc123",
            "trades": 50,
            "rating": 0.98
        }
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_self_user()
        
        mock_request.assert_called_once_with('GET', 'user/me', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_self_payment_method_info(self, mock_request):
        """Test get self payment methods."""
        mock_request.return_value = {"methods": ["sepa", "paypal"]}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_self_payment_method_info()
        
        mock_request.assert_called_once_with('GET', 'user/me/paymentMethods', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_self_trading_limits(self, mock_request):
        """Test get trading limits."""
        mock_request.return_value = {"daily": 1000000, "used": 50000}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_self_trading_limits()
        
        mock_request.assert_called_once_with('GET', 'user/tradingLimit', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_user_status(self, mock_request):
        """Test get user status."""
        mock_request.return_value = {"status": "active"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_user_status("02abc123")
        
        mock_request.assert_called_once_with('GET', 'user/02abc123/status', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_block_user(self, mock_request):
        """Test block user."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.block_user("02abc123")
        
        mock_request.assert_called_once_with('PUT', 'user/02abc123/block', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_unblock_user(self, mock_request):
        """Test unblock user."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.unblock_user("02abc123")
        
        mock_request.assert_called_once_with('DELETE', 'user/02abc123/block', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_user_manage_batching_enable(self, mock_request):
        """Test enable batching."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.user_manage_batching(True)
        
        mock_request.assert_called_once_with(
            'PATCH', 'user/batching',
            data={"enableBatching": True},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_user_redeem_referral_code(self, mock_request):
        """Test redeem referral code."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.user_redeem_referral_code("TESTCODE")
        
        mock_request.assert_called_once_with(
            'PATCH', 'user/referral/redeem/referralCode',
            data={"code": "TESTCODE"},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_user_redeem_free_trades(self, mock_request):
        """Test redeem free trades."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.user_redeem_free_trades()
        
        mock_request.assert_called_once_with(
            'PATCH', 'user/referral/redeem/fiveFreeTrades',
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_user_unlink_payment_hashes(self, mock_request):
        """Test unlink payment hashes."""
        mock_request.return_value = {"success": True}
        hashes = ["hash1", "hash2"]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.user_unlink_payment_hashes(hashes)
        
        mock_request.assert_called_once_with(
            'PATCH', 'user/paymentHash',
            data={"hashes": hashes},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_logout(self, mock_request):
        """Test logout."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.logout()
        
        mock_request.assert_called_once_with('PATCH', 'user/logout', requires_auth=True)


# =============================================================================
# PEACH WRAPPER - PRIVATE OFFER ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestPrivateOfferEndpoints:
    """Tests for private offer API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_own_offers(self, mock_request):
        """Test get own offers."""
        mock_request.return_value = [{"id": "123", "type": "bid"}]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_own_offers()
        
        mock_request.assert_called_once_with('GET', 'offers', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_own_offers_summaries(self, mock_request):
        """Test get offer summaries."""
        mock_request.return_value = {"total": 5, "active": 2}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_own_offers_summaries()
        
        mock_request.assert_called_once_with('GET', 'offers/summary', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_own_offer_details(self, mock_request):
        """Test get offer details."""
        mock_request.return_value = {"id": "123", "type": "bid", "amount": [50000, 100000]}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_own_offer_details("123")
        
        mock_request.assert_called_once_with('GET', 'offer/123/details', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_create_escrow(self, mock_request):
        """Test create escrow."""
        mock_request.return_value = {"escrowAddress": "bc1q...", "funding": 21000}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.create_escrow("123", "02pubkey...")
        
        mock_request.assert_called_once_with(
            'POST', 'offer/123/escrow',
            data={'publicKey': '02pubkey...'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_funding_status(self, mock_request):
        """Test get funding status."""
        mock_request.return_value = {"funded": True, "confirmations": 3}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_funding_status("123")
        
        mock_request.assert_called_once_with('GET', 'offer/123/escrow', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_confirm_escrow_funding(self, mock_request):
        """Test confirm escrow funding."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.confirm_escrow_funding("123")
        
        mock_request.assert_called_once_with('POST', 'offer/123/escrow/confirm', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_cancel_offer(self, mock_request):
        """Test cancel offer."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.cancel_offer("123")
        
        mock_request.assert_called_once_with('POST', 'offer/123/cancel', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_refund_psbt(self, mock_request):
        """Test get refund PSBT."""
        mock_request.return_value = {"psbt": "cHNidP8..."}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_refund_psbt("123")
        
        mock_request.assert_called_once_with('GET', 'offer/123/refundPsbt', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_refund_sell_offer(self, mock_request):
        """Test refund sell offer."""
        mock_request.return_value = {"txid": "abc..."}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.refund_sell_offer("123", "0100000001...")
        
        mock_request.assert_called_once_with(
            'POST', 'offer/123/refund',
            data={'tx': '0100000001...'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_republish_sell_offer(self, mock_request):
        """Test republish sell offer."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.republish_sell_offer("123")
        
        mock_request.assert_called_once_with('POST', 'offer/123/revive', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_update_buy_offer(self, mock_request):
        """Test update buy offer."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.update_buy_offer("123", amount_range=(60000, 120000), max_premium=5)
        
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[0][0] == 'PATCH'
        assert call_args[0][1] == 'offer/123'
        assert call_args[1]['data']['amount'] == [60000, 120000]
        assert call_args[1]['data']['maxPremium'] == 5
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_update_sell_offer(self, mock_request):
        """Test update sell offer."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.update_sell_offer("123", amount=50000, premium=3)
        
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[1]['data']['amount'] == 50000
        assert call_args[1]['data']['premium'] == 3


# =============================================================================
# PEACH WRAPPER - MATCH ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestMatchEndpoints:
    """Tests for match API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_matches(self, mock_request):
        """Test get matches."""
        mock_request.return_value = [{"offerId": "456", "price": 28000}]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_matches("123")
        
        mock_request.assert_called_once_with('GET', 'offer/123/matches', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_match_sell_offer(self, mock_request):
        """Test match sell offer."""
        mock_request.return_value = {"contractId": "123-456"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.match_sell_offer(
            offer_id="123",
            match_offer_id="456",
            price=28000.0,
            currency="EUR",
            payment_method="sepa",
            symmetric_key_encrypted="encrypted_key",
            symmetric_key_signature="key_sig",
            payment_data_encrypted="encrypted_data",
            payment_data_signature="data_sig"
        )
        
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[0][0] == 'POST'
        assert call_args[0][1] == 'offer/123/match'
        assert call_args[1]['data']['matchingOfferId'] == '456'
        assert call_args[1]['data']['price'] == 28000.0
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_unmatch_sell_offer(self, mock_request):
        """Test unmatch sell offer."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.unmatch_sell_offer("123", "456")
        
        mock_request.assert_called_once_with(
            'POST', 'offer/123/match/undo',
            data={'matchingOfferId': '456'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_doublematch_buy_offer(self, mock_request):
        """Test doublematch buy offer."""
        mock_request.return_value = {"contractId": "456-123"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.doublematch_buy_offer(
            offer_id="456",
            match_offer_id="123",
            currency="EUR",
            payment_method="sepa",
            symmetric_key_encrypted="encrypted_key",
            symmetric_key_signature="key_sig",
            payment_data_encrypted="encrypted_data",
            payment_data_signature="data_sig"
        )
        
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[0][0] == 'POST'
        assert call_args[0][1] == 'offer/456/doublematch'


# =============================================================================
# PEACH WRAPPER - CONTRACT ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestContractEndpoints:
    """Tests for contract API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_contracts(self, mock_request):
        """Test get all contracts."""
        mock_request.return_value = [{"id": "123-456", "status": "active"}]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_contracts()
        
        mock_request.assert_called_once_with('GET', 'contracts', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_contract_summaries(self, mock_request):
        """Test get contract summaries."""
        mock_request.return_value = [{"id": "123-456", "tradeStatus": "paymentRequired"}]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_contract_summaries()
        
        mock_request.assert_called_once_with('GET', 'contracts/summary', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_contract_details(self, mock_request):
        """Test get contract details."""
        mock_request.return_value = {
            "id": "123-456",
            "buyer": "02abc...",
            "seller": "02def...",
            "amount": 21000,
            "releasePsbt": "cHNidP8..."
        }
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_contract_details("123-456")
        
        mock_request.assert_called_once_with('GET', 'contract/123-456', requires_auth=True)
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_confirm_payment_made(self, mock_request):
        """Test confirm payment made (buyer action)."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.confirm_payment_made("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/payment/confirm',
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_confirm_payment_received_without_tx(self, mock_request):
        """Test confirm payment received without release transaction."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.confirm_payment_received("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/payment/confirm',
            data={},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_confirm_payment_received_with_tx(self, mock_request):
        """Test confirm payment received with release transaction (seller action)."""
        mock_request.return_value = {"txid": "abc123..."}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.confirm_payment_received("123-456", release_transaction="0100000001...")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/payment/confirm',
            data={'releaseTransaction': '0100000001...'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_rate_counterparty(self, mock_request):
        """Test rate counterparty."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.rate_counterparty("123-456", rating=5, signature="sig123")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/rating',
            data={'rating': 5, 'signature': 'sig123'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_cancel_contract_without_reason(self, mock_request):
        """Test cancel contract without reason."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.cancel_contract("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/cancel',
            data={},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_cancel_contract_with_reason(self, mock_request):
        """Test cancel contract with reason."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.cancel_contract("123-456", reason="Changed my mind")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/cancel',
            data={'reason': 'Changed my mind'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_confirm_cancelation_request(self, mock_request):
        """Test confirm cancellation request."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.confirm_cancelation_request("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/cancel/confirm',
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_reject_cancelation_request(self, mock_request):
        """Test reject cancellation request."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.reject_cancelation_request("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/cancel/reject',
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_extend_payment_time(self, mock_request):
        """Test extend payment time."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.extend_payment_time("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/extend',
            requires_auth=True
        )


# =============================================================================
# PEACH WRAPPER - CHAT ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestChatEndpoints:
    """Tests for chat API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_chat_log(self, mock_request):
        """Test get chat log."""
        mock_request.return_value = [
            {"id": "msg1", "message": "encrypted...", "from": "02abc..."}
        ]
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_chat_log("123-456")
        
        mock_request.assert_called_once_with(
            'GET', 'contract/123-456/chat',
            params={'page': 0},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_get_chat_log_with_page(self, mock_request):
        """Test get chat log with pagination."""
        mock_request.return_value = []
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.get_chat_log("123-456", page=2)
        
        mock_request.assert_called_once_with(
            'GET', 'contract/123-456/chat',
            params={'page': 2},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_post_chat_message(self, mock_request):
        """Test post chat message."""
        mock_request.return_value = {"messageId": "msg2"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.post_chat_message("123-456", "encrypted_message", "signature")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/chat',
            data={'message': 'encrypted_message', 'signature': 'signature'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_set_chat_message_read(self, mock_request):
        """Test mark message as read."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.set_chat_message_read("123-456", "msg1")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/chat/msg1/read',
            requires_auth=True
        )


# =============================================================================
# PEACH WRAPPER - DISPUTE ENDPOINT TESTS (MOCKED)
# =============================================================================

class TestDisputeEndpoints:
    """Tests for dispute API endpoints using mocks."""
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_raise_dispute_without_email(self, mock_request):
        """Test raise dispute without email."""
        mock_request.return_value = {"disputeId": "disp1"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.raise_dispute("123-456", reason="Non-payment")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/dispute',
            data={'reason': 'Non-payment'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_raise_dispute_with_email(self, mock_request):
        """Test raise dispute with email."""
        mock_request.return_value = {"disputeId": "disp1"}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.raise_dispute("123-456", reason="Non-payment", email="test@example.com")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/dispute',
            data={'reason': 'Non-payment', 'email': 'test@example.com'},
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_acknowledge_dispute(self, mock_request):
        """Test acknowledge dispute."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.acknowledge_dispute("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/dispute/acknowledge',
            requires_auth=True
        )
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_acknowledge_dispute_outcome(self, mock_request):
        """Test acknowledge dispute outcome."""
        mock_request.return_value = {"success": True}
        
        wrapper = PeachWrapper(access_token="test-token")
        result = wrapper.acknowledge_dispute_outcome("123-456")
        
        mock_request.assert_called_once_with(
            'POST', 'contract/123-456/dispute/outcome/acknowledge',
            requires_auth=True
        )


# =============================================================================
# INTEGRATION-STYLE TESTS (Testing full flow logic)
# =============================================================================

class TestTradingFlow:
    """Tests simulating the complete trading flow from the blog post."""
    
    def test_payment_data_hash_matches_expected(self):
        """Test that payment data hashing works correctly for trading."""
        # Simulating what the blog shows
        payment_info = {"userName": "@myWiseIdTradingBot"}
        pd = PeachPaymentData("wise", **payment_info)
        
        payment_type, hash_result = pd.create_hash()
        
        # Verify the hash is a valid SHA256
        assert len(hash_result["hashes"][0]) == 64  # SHA256 hex length
        assert all(c in "0123456789abcdef" for c in hash_result["hashes"][0])
    
    def test_means_of_payment_for_sell_offer(self):
        """Test means of payment structure for sell offers."""
        # From blog: { [payment_data_currency]: [payment_data_method] }
        mop = PeachMeansOfPayment({"EUR": ["wise"]})
        
        result = mop.get()
        
        assert result == {"EUR": ["wise"]}
    
    @patch.object(PeachWrapper, '_PeachWrapper__send_request')
    def test_full_sell_offer_creation_flow(self, mock_request):
        """Test the complete sell offer creation flow."""
        mock_request.return_value = {"id": "offer123"}
        
        wrapper = PeachWrapper(access_token="test-token")
        wrapper.user_id = "02testuser..."
        
        # Create payment data (as shown in blog)
        pd = PeachPaymentData("wise", userName="@myWiseIdTradingBot")
        mop = PeachMeansOfPayment({"EUR": ["wise"]})
        
        # This should work
        result = wrapper.post_sell_offer(
            amount=21000,
            returnAddress="bc1q...",
            paymentData=[pd],
            meansOfPayment=mop,
            premium=1
        )
        
        # Verify the request structure
        call_args = mock_request.call_args
        data = call_args[1]['data']
        
        assert data['type'] == 'ask'
        assert data['amount'] == 21000
        assert data['premium'] == 1
        assert 'wise' in data['paymentData']
        assert 'hashes' in data['paymentData']['wise']


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Tests for error handling scenarios."""
    
    def test_requires_auth_without_token(self):
        """Test that auth-required endpoints fail without token."""
        wrapper = PeachWrapper()
        
        with pytest.raises(PeachBTCError) as excinfo:
            wrapper.get_self_user()
        
        assert "Access token required" in str(excinfo.value.message)
    
    @patch.object(PeachWrapper, '_PeachWrapper__sign_message')
    def test_invalid_private_key_handling(self, mock_sign):
        """Test handling of invalid private key."""
        mock_sign.side_effect = PeachBTCError("Invalid private key")
        
        wrapper = PeachWrapper(private_key_hex="invalid")
        
        with pytest.raises(PeachBTCError) as excinfo:
            wrapper.set_access_token()
        
        assert "Invalid private key" in str(excinfo.value)


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

