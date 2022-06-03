import os
import pytest
from unittest.mock import patch

import impacket

import arg_parser
import scan
import scan_internals

class TestIsValidPath:
  logDirectory = os.path.join(os.getcwd())

  def assert_is_valid_path(self, path, expectedResult):
    assert(scan_internals.is_valid_path(self.logDirectory, path) == expectedResult)

  def test_normal_path(self):
    self.assert_is_valid_path('normal', True)
  
  def test_bad_path(self):
    self.assert_is_valid_path('/bad', False)

  def test_traversal_path(self):
    self.assert_is_valid_path('..', False)

def test_get_shares(test_client):
  shares = scan_internals.get_shares(test_client)
  
  assert(len(shares) == 2)
  assert(shares[0].shareName == "Admin")
  assert(shares[1].shareName == "TestShare")

def test_get_client(test_target, test_user, test_options):
  with patch.object(impacket.smbconnection.SMBConnection, '__init__', mock_connection_init):
    with patch.object(impacket.smbconnection.SMBConnection, 'login', mock_login):
      port = 445
      client = scan_internals.get_client(test_target, test_user, test_options, port)
      
      assert(client != None)
      assert(client._remoteHost == test_target.ip)

def mock_connection_init(self, remoteName='', remoteHost='', myName=None, sess_port=impacket.nmb.SMB_SESSION_PORT, 
                         timeout=60, preferredDialect=None, existingConnection=None, manualNegotiate=False):
  """Mock SMBConnection constructor and return default values."""
  self._SMBConnection         = 0
  self._dialect               = ''
  self._nmbSession            = 0
  self._sess_port             = sess_port
  self._myName                = myName
  self._remoteHost            = remoteHost
  self._remoteName            = remoteName
  self._timeout               = timeout
  self._preferredDialect      = preferredDialect
  self._existingConnection    = existingConnection
  self._manualNegotiate       = manualNegotiate
  self._doKerberos            = False
  self._kdcHost               = None
  self._useCache              = True
  self._ntlmFallback          = True

def mock_login(self, user, password, domain = '', lmhash = '', nthash = '', ntlmFallback = True):
  """Mock SMBConnection login() and return None"""
  return None

@pytest.fixture
def test_target():
  ip = '127.0.0.1'
  return scan.Target(ip)

@pytest.fixture
def test_user():
  return scan.User()

@pytest.fixture
def test_options():
  return arg_parser.Options()

@pytest.fixture
def test_client():
  class TestClient:
    def listShares(self):
      return [
        {"shi1_netname": "IPC$\\"},
        {"shi1_netname": "Admin\\"},
        {"shi1_netname": "TestShare\\"} 
      ]
  return TestClient()
