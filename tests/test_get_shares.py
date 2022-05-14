import pytest

import scan_internals


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

@pytest.fixture
def test_target():
  class TestTarget:
    def __init__(self):
        self.shares      = []
    
  return TestTarget()


def test_get_shares(test_client, test_target):
  scan_internals.get_shares(test_client, test_target)
  print(test_target.shares)
  
  assert(len(test_target.shares) == 2)
  assert(test_target.shares[0].shareName == "Admin$")
  assert(test_target.shares[1].shareName == "TestShare$")
