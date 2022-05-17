import pytest

import scan_internals

def test_get_shares(test_client):
  shares = scan_internals.get_shares(test_client)
  
  assert(len(shares) == 2)
  assert(shares[0].shareName == "Admin$")
  assert(shares[1].shareName == "TestShare$")

@pytest.fixture
def test_client():
  class TestClient:
    def listShares(self):
      return [
        {"shi1_netname": "IPC$\\"},
        {"shi1_netname": "Admin$\\"},
        {"shi1_netname": "TestShare$\\"} 
      ]
  
  return TestClient()
