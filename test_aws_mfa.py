import mock
import sys
import pytest
import shutil
# import aws_mfa
import os
import boto3

from unittest.mock import Mock
from configparser import ConfigParser
from moto import mock_sts
# from aws_mfa import AwsMfa

EXPECTED_MFA_DEV_ARN = 'arn:aws:iam::123456789012:mfa/user'

@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    '''
    Environment setup before all tests
    '''
    monkeypatch.delenv('AWS_DEFAULT_REGION')
    monkeypatch.delenv('AWS_MFA_PROFILE')
    monkeypatch.delenv('AWS_MFA_YK_OATH_CREDENTIAL')
    monkeypatch.delenv('AWS_PROFILE')

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user', '--duration', '666'])
def test_get_cli_argument(monkeypatch, tmp_path):
    '''
    Test loading a config param from CLI
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    duration = aws_mfa._get_argument('duration')
    assert(duration == 666)

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user2', '--duration', '666'])
def test_get_config_argument(monkeypatch, tmp_path):
    '''
    Test loading a config param from config profile
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    oath_credential = aws_mfa._get_argument('yk_oath_credential')
    assert(oath_credential == 'test_oath_cred')

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user'])
def test_recursive_get_config_param(monkeypatch, tmp_path):
    '''
    Test loading a config param present in a parent profile
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    mfa_serial = AwsMfa.recursive_get_config_param(aws_mfa.config, 'profile role', 'mfa_serial')
    assert(mfa_serial == EXPECTED_MFA_DEV_ARN)

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykman_is_installed(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    assert(aws_mfa._ykman_is_installed())

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    assert(aws_mfa._ykey_is_present())

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    with pytest.raises(RuntimeError):
        assert(aws_mfa._ykey_is_present(ykey_count=0))

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user', '--yk-oath-credential', 'foo'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    with mock.patch.object(AwsMfa, '_ykman_is_installed', return_value=False):
        aws_mfa = AwsMfa()
        with pytest.raises(RuntimeError):
            assert(aws_mfa._ykey_is_present(ykey_count=0) == False)

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--mfa-profile', 'user', '--yk-oath-credential', 'foo'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    with mock.patch.object(AwsMfa, '_get_ykey_token', return_value=123456):
        with mock.patch.object(AwsMfa, '_ykey_is_present', return_value=True):
            aws_mfa = AwsMfa()
            assert(aws_mfa._get_token() == 123456)

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user',])
@mock_sts
def test_get_mfa_creds_expired(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    updated, creds = aws_mfa._get_mfa_creds()
    print(creds['expiration'])
    print(updated)
    assert(updated == True)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user'])
@mock_sts
def test_get_mfa_creds_unexpired(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'unexpired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    updated, creds = aws_mfa._get_mfa_creds()
    assert(updated == False)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'user', '--write-env-file'])
@mock_sts
def test_invoke_unexpired_creds(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_MFA_DURATION', '900')
    init_tmpdir(tmp_path, 'unexpired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    aws_mfa.invoke()
    assert(aws_mfa._get_argument('duration') == '900')

@mock.patch.object(sys, 'argv', ['aws_mfa.py', '--token', '123456', '--mfa-profile', 'role', '--write-env-file'])
@mock_sts
def test_invoke_expired_creds(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from aws_mfa import AwsMfa
    aws_mfa = AwsMfa()
    aws_mfa.invoke()

def init_tmpdir(tmp_dir, status):
    os.mkdir(f'{tmp_dir}/.aws')
    shutil.copyfile(f'./test_data/config', f'{tmp_dir}/.aws/config')
    shutil.copyfile(f'./test_data/credentials_{status}', f'{tmp_dir}/.aws/credentials')
