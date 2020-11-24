#!/usr/bin/env python

import os
import shutil
import sys
from configparser import ConfigParser
from unittest.mock import Mock

import mock
import pytest
from moto import mock_sts

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

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user', '--duration', '666'])
def test_get_cli_argument(monkeypatch, tmp_path):
    '''
    Test loading a config param from CLI
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    duration = cli._get_argument('duration')
    assert(duration == 666)

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user2', '--duration', '666'])
def test_get_config_argument(monkeypatch, tmp_path):
    '''
    Test loading a config param from config profile
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    oath_credential = cli._get_argument('yk_oath_credential')
    assert(oath_credential == 'test_oath_cred')

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user'])
def test_recursive_get_config_param(monkeypatch, tmp_path):
    '''
    Test loading a config param present in a parent profile
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    mfa_serial = CLI.recursive_get_config_param(cli.config, 'profile role', 'mfa_serial')
    assert(mfa_serial == EXPECTED_MFA_DEV_ARN)

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykman_is_installed(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    assert(cli._ykman_is_installed())

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    assert(cli._ykey_is_present())

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    with pytest.raises(RuntimeError):
        assert(cli._ykey_is_present(ykey_count=0))

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user', '--yk-oath-credential', 'foo'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    with mock.patch.object(CLI, '_ykman_is_installed', return_value=False):
        cli = CLI()
        with pytest.raises(RuntimeError):
            assert(cli._ykey_is_present(ykey_count=0) == False)

@mock.patch.object(sys, 'argv', ['cli.py', '--mfa-profile', 'user', '--yk-oath-credential', 'foo'])
@pytest.mark.skipif(shutil.which('ykman') is None, reason="ykman is not installed")
def test_ykey_is_not_present(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    with mock.patch.object(CLI, '_get_ykey_token', return_value=123456):
        with mock.patch.object(CLI, '_ykey_is_present', return_value=True):
            cli = CLI()
            assert(cli._get_token() == 123456)

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user',])
@mock_sts
def test_get_mfa_creds_expired(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    updated, creds = cli._get_mfa_creds()
    print(creds['expiration'])
    print(updated)
    assert(updated == True)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user'])
@mock_sts
def test_get_mfa_creds_unexpired(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'unexpired')
    from awsmfav2.cli import CLI
    cli = CLI()
    updated, creds = cli._get_mfa_creds()
    assert(updated == False)
    assert(isinstance(creds['aws_access_key_id'], str))
    assert(isinstance(creds['aws_secret_access_key'], str))
    assert(isinstance(creds['aws_session_token'], str))
    assert(isinstance(creds['expiration'], str))

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'user', '--write-env-file'])
@mock_sts
def test_main_unexpired_creds(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_MFA_DURATION', '900')
    init_tmpdir(tmp_path, 'unexpired')
    from awsmfav2.cli import CLI
    cli = CLI()
    cli.main()
    assert(cli._get_argument('duration') == '900')

@mock.patch.object(sys, 'argv', ['cli.py', '--token', '123456', '--mfa-profile', 'role', '--write-env-file'])
@mock_sts
def test_main_expired_creds(monkeypatch, tmp_path):
    '''
    Test that we can actually call mock STS and get back creds
    '''
    monkeypatch.setenv('HOME', str(tmp_path))
    init_tmpdir(tmp_path, 'expired')
    from awsmfav2.cli import CLI
    cli = CLI()
    cli.main()

def init_tmpdir(tmp_dir, status):
    dirpath = os.path.dirname(__file__)
    config_filepath = os.path.join(dirpath, 'test_data/config')
    creds_filepath = os.path.join(dirpath, f'./test_data/credentials_{status}')
    os.mkdir(f'{tmp_dir}/.aws')
    shutil.copyfile(config_filepath, f'{tmp_dir}/.aws/config')
    shutil.copyfile(creds_filepath, f'{tmp_dir}/.aws/credentials')
