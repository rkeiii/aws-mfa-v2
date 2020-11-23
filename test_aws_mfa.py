import mock
import sys
import pytest
import shutil
import aws_mfa
import os
import boto3

from mock import Mock
from aws_mfa import AwsMfa
from configparser import ConfigParser
from moto import mock_sts

EXPECTED_MFA_DEV_ARN = 'arn:aws:iam::123456789012:mfa/user'

@pytest.fixture(scope='function')
@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--mfa-profile', 'user'])
@mock.patch.object(aws_mfa, 'AWS_CONFIG_PATH', './test_data/config')
@mock.patch.object(aws_mfa, 'AWS_CREDS_PATH', './test_data/credentials_unexpired')
def aws_mfa_unexpired_creds():
    '''
    Return an AwsMfa instance with valid creds
    '''
    return AwsMfa()

@pytest.fixture(scope='function')
@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--mfa-profile', 'user', '--token', '123456'])
@mock.patch.object(aws_mfa, 'AWS_CONFIG_PATH', './test_data/config')
@mock.patch.object(aws_mfa, 'AWS_CREDS_PATH', './test_data/credentials_expired')
@mock.patch.object(os, 'environ', {'AWS_MFA_PROFILE': 'user','HOME': './test_data'})
@mock_sts
def aws_mfa_expired_creds():
    '''
    Return an AwsMfa instance with expired creds
    '''
    return AwsMfa()

def test_recursive_get_config_param(aws_mfa_unexpired_creds):
    '''
    Test loading 
    '''
    mfa_serial = AwsMfa.recursive_get_config_param(aws_mfa_unexpired_creds.config, 'profile user-mfa', 'mfa_serial')
    assert(mfa_serial == EXPECTED_MFA_DEV_ARN)

@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykman_is_installed(aws_mfa_unexpired_creds):
    assert(aws_mfa_unexpired_creds._ykman_is_installed())

@mock_sts
@mock.patch.object(os, 'environ', {'HOME': './test_data'})
def test_get_mfa_creds_expired(aws_mfa_expired_creds):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    updated, creds = aws_mfa_expired_creds._get_mfa_creds()
    assert(updated == True)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))

@mock.patch.object(os, 'environ', {'HOME': './test_data'})
def test_get_mfa_creds_unexpired(aws_mfa_unexpired_creds):
    '''
    Test that we can load existing credentials from local storage
    '''
    updated, creds = aws_mfa_unexpired_creds._get_mfa_creds()
    assert(updated == False)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))